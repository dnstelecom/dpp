/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use hickory_proto::op::response_code::ResponseCode as HickoryResponseCode;
use std::collections::BTreeMap;

use super::DnsProcessor;
use super::types::{
    MatcherShardState, ProcessedDnsRecord, QueryEventPayload, QueryIdentityKey,
    ResponseEventPayload, ResponseIdentityKey, ShardProcessingResult, Timeline, TimelineKey,
};
use crate::custom_types::{ProtoRecordType, ProtoResponseCode};
use crate::record::DnsRecord;

#[cfg(test)]
use super::types::DnsQuery;

impl DnsProcessor {
    fn remove_timeline_entry<Identity, Record>(
        map: &mut BTreeMap<Identity, Timeline<Record>>,
        identity: &Identity,
        key: TimelineKey,
    ) -> Option<Record>
    where
        Identity: Ord,
    {
        let mut remove_identity = false;

        let removed = if let Some(timeline) = map.get_mut(identity) {
            let removed = timeline.remove(key);
            remove_identity = timeline.is_empty();
            removed
        } else {
            None
        };

        if remove_identity {
            map.remove(identity);
        }

        removed
    }

    fn create_matched_record_from_query_parts(
        query_identity: &QueryIdentityKey,
        query_key: TimelineKey,
        response_timestamp_micros: i64,
        response_code: HickoryResponseCode,
    ) -> DnsRecord {
        let &(id, name, src_ip, src_port, query_type) = query_identity;
        DnsRecord {
            request_timestamp: query_key.timestamp_micros,
            response_timestamp: response_timestamp_micros,
            source_ip: src_ip,
            source_port: src_port,
            id,
            name,
            query_type: ProtoRecordType::from(query_type),
            response_code: ProtoResponseCode::from(response_code),
        }
    }

    fn create_timeout_record_from_query_parts(
        query_identity: &QueryIdentityKey,
        query_key: TimelineKey,
    ) -> DnsRecord {
        let &(id, name, src_ip, src_port, query_type) = query_identity;
        DnsRecord {
            request_timestamp: query_key.timestamp_micros,
            response_timestamp: 0,
            source_ip: src_ip,
            source_port: src_port,
            id,
            name,
            query_type: ProtoRecordType::from(query_type),
            response_code: ProtoResponseCode::from(HickoryResponseCode::ServFail),
        }
    }

    fn has_pending_query_before(
        &self,
        state: &MatcherShardState,
        identity: &QueryIdentityKey,
        timestamp_micros: i64,
    ) -> bool {
        let Some(timeline) = state.query_map.get(&identity) else {
            return false;
        };

        timeline.contains_timestamp_range(
            timestamp_micros.saturating_sub(self.match_timeout_micros),
            timestamp_micros,
        )
    }

    fn process_query(
        &self,
        record: &ProcessedDnsRecord,
        state: &mut MatcherShardState,
        output_records: &mut Vec<DnsRecord>,
        dns_query_count: &mut usize,
        duplicated_query_count: &mut usize,
        matched_query_response_count: &mut usize,
        matched_rtt_sum_micros: &mut u64,
    ) {
        let query_identity = self.query_identity_from_record(record);
        let query_key = self.timeline_key_from_record(record);
        *dns_query_count += 1;

        if self.has_pending_query_before(state, &query_identity, query_key.timestamp_micros) {
            *duplicated_query_count += 1;
            return;
        }

        if let Some((_, response_handle)) = self.find_closest_response(
            state,
            &query_identity,
            query_key.timestamp_micros,
            query_key
                .timestamp_micros
                .saturating_add(self.match_timeout_micros),
            query_key.timestamp_micros,
        ) {
            let response_payload = self
                .remove_response_entry(state, &query_identity, response_handle)
                .expect("matched response handle must remain valid until removal");
            output_records.push(DnsProcessor::create_matched_record_from_query_parts(
                &query_identity,
                query_key,
                response_handle.timestamp_micros,
                response_payload.response_code,
            ));
            *matched_query_response_count += 1;
            *matched_rtt_sum_micros += response_handle
                .timestamp_micros
                .saturating_sub(query_key.timestamp_micros)
                .max(0) as u64;
        } else {
            self.insert_query_entry(state, query_identity, query_key);
        }
    }

    fn process_response(
        &self,
        record: &ProcessedDnsRecord,
        state: &mut MatcherShardState,
        output_records: &mut Vec<DnsRecord>,
        dns_response_count: &mut usize,
        matched_query_response_count: &mut usize,
        matched_rtt_sum_micros: &mut u64,
    ) {
        let response_identity = self.response_identity_from_record(record);
        let response_key = self.timeline_key_from_record(record);
        *dns_response_count += 1;

        if let Some((_, query_handle)) = self.find_closest_query(
            state,
            &response_identity,
            response_key
                .timestamp_micros
                .saturating_sub(self.match_timeout_micros),
            response_key.timestamp_micros,
            response_key.timestamp_micros,
        ) {
            self.remove_query_entry(state, &response_identity, query_handle)
                .expect("matched query handle must remain valid until removal");
            output_records.push(DnsProcessor::create_matched_record_from_query_parts(
                &response_identity,
                query_handle,
                response_key.timestamp_micros,
                record.response_code,
            ));
            *matched_query_response_count += 1;
            *matched_rtt_sum_micros += response_key
                .timestamp_micros
                .saturating_sub(query_handle.timestamp_micros)
                .max(0) as u64;
        } else {
            self.insert_response_entry(
                state,
                response_identity,
                response_key,
                record.response_code,
            );
        }
    }

    fn process_remaining_queries(
        &self,
        state: &mut MatcherShardState,
        output_records: &mut Vec<DnsRecord>,
        matched_query_response_count: &mut usize,
        timeout_query_count: &mut usize,
        matched_rtt_sum_micros: &mut u64,
        out_of_order_combined_count: &mut usize,
    ) {
        while let Some((query_identity, timeline)) = state.query_map.pop_first() {
            timeline.into_entries(|query_handle, _| {
                let query_timestamp = query_handle.timestamp_micros;

                if let Some((_, response_handle)) = self.find_closest_response(
                    state,
                    &query_identity,
                    query_timestamp,
                    query_timestamp.saturating_add(self.match_timeout_micros),
                    query_timestamp,
                ) {
                    let response_payload = self
                        .remove_response_entry(state, &query_identity, response_handle)
                        .expect("matched response handle must remain valid until removal");
                    output_records.push(DnsProcessor::create_matched_record_from_query_parts(
                        &query_identity,
                        query_handle,
                        response_handle.timestamp_micros,
                        response_payload.response_code,
                    ));
                    *matched_query_response_count += 1;
                    *matched_rtt_sum_micros += response_handle
                        .timestamp_micros
                        .saturating_sub(query_handle.timestamp_micros)
                        .max(0) as u64;
                    *out_of_order_combined_count += 1;
                } else {
                    output_records.push(DnsProcessor::create_timeout_record_from_query_parts(
                        &query_identity,
                        query_handle,
                    ));
                    *timeout_query_count += 1;
                }
            });
        }
    }

    fn evict_queries_before(
        &self,
        state: &mut MatcherShardState,
        threshold_timestamp_micros: i64,
        output_records: &mut Vec<DnsRecord>,
        timeout_query_count: &mut usize,
    ) {
        let query_map = &mut state.query_map;

        query_map.retain(|identity, timeline| {
            timeline.drain_before(threshold_timestamp_micros, |key, _| {
                output_records.push(DnsProcessor::create_timeout_record_from_query_parts(
                    identity, key,
                ));
                *timeout_query_count += 1;
            });
            !timeline.is_empty()
        });
    }

    fn evict_responses_before(
        &self,
        state: &mut MatcherShardState,
        threshold_timestamp_micros: i64,
    ) {
        let response_map = &mut state.response_map;

        response_map.retain(|_, timeline| {
            timeline.drain_before(threshold_timestamp_micros, |_, _| {});
            !timeline.is_empty()
        });
    }

    fn apply_batched_timeout_eviction(
        &self,
        max_timestamp_micros: i64,
        state: &mut MatcherShardState,
        output_records: &mut Vec<DnsRecord>,
        timeout_query_count: &mut usize,
    ) {
        let threshold_timestamp_micros =
            max_timestamp_micros.saturating_sub(self.match_timeout_micros);

        self.evict_queries_before(
            state,
            threshold_timestamp_micros,
            output_records,
            timeout_query_count,
        );
        self.evict_responses_before(state, threshold_timestamp_micros);
    }

    pub(super) fn insert_query_entry(
        &self,
        state: &mut MatcherShardState,
        identity: QueryIdentityKey,
        timeline_key: TimelineKey,
    ) {
        let replaced = state
            .query_map
            .entry(identity)
            .or_default()
            .insert(timeline_key, QueryEventPayload);

        if replaced.is_some() {
            debug_assert!(
                false,
                "query timeline unexpectedly replaced an existing payload for identical identity/timeline key"
            );
        }
    }

    pub(super) fn insert_response_entry(
        &self,
        state: &mut MatcherShardState,
        identity: ResponseIdentityKey,
        timeline_key: TimelineKey,
        response_code: HickoryResponseCode,
    ) {
        let payload = ResponseEventPayload { response_code };

        let replaced = state
            .response_map
            .entry(identity)
            .or_default()
            .insert(timeline_key, payload);

        if replaced.is_some() {
            debug_assert!(
                false,
                "response timeline unexpectedly replaced an existing payload for identical identity/timeline key"
            );
        }
    }

    fn remove_query_entry(
        &self,
        state: &mut MatcherShardState,
        identity: &QueryIdentityKey,
        timeline_key: TimelineKey,
    ) -> Option<QueryEventPayload> {
        Self::remove_timeline_entry(&mut state.query_map, identity, timeline_key)
    }

    fn remove_response_entry(
        &self,
        state: &mut MatcherShardState,
        identity: &ResponseIdentityKey,
        timeline_key: TimelineKey,
    ) -> Option<ResponseEventPayload> {
        Self::remove_timeline_entry(&mut state.response_map, identity, timeline_key)
    }

    pub(super) fn find_closest_response(
        &self,
        state: &MatcherShardState,
        response_identity: &ResponseIdentityKey,
        lower_timestamp_micros: i64,
        upper_timestamp_micros: i64,
        query_timestamp_micros: i64,
    ) -> Option<(i64, TimelineKey)> {
        let timeline = state.response_map.get(response_identity)?;
        let (response_key, _) =
            timeline.first_entry_in_range(lower_timestamp_micros, upper_timestamp_micros)?;

        Some((
            response_key.timestamp_micros - query_timestamp_micros,
            response_key,
        ))
    }

    pub(super) fn find_closest_query(
        &self,
        state: &MatcherShardState,
        query_identity: &QueryIdentityKey,
        lower_timestamp_micros: i64,
        upper_timestamp_micros: i64,
        response_timestamp_micros: i64,
    ) -> Option<(i64, TimelineKey)> {
        let timeline = state.query_map.get(query_identity)?;
        let (query_key, _) =
            timeline.last_entry_in_range(lower_timestamp_micros, upper_timestamp_micros)?;
        let time_diff = response_timestamp_micros.checked_sub(query_key.timestamp_micros)?;

        Some((time_diff, query_key))
    }

    fn query_identity_from_record(&self, record: &ProcessedDnsRecord) -> QueryIdentityKey {
        let (src_ip, src_port) = if record.is_query {
            (self.anonymize_ip(&record.src_ip), record.src_port)
        } else {
            (self.anonymize_ip(&record.dst_ip), record.dst_port)
        };

        (record.id, record.name, src_ip, src_port, record.query_type)
    }

    fn response_identity_from_record(&self, record: &ProcessedDnsRecord) -> ResponseIdentityKey {
        let (dst_ip, dst_port) = if record.is_query {
            (self.anonymize_ip(&record.src_ip), record.src_port)
        } else {
            (self.anonymize_ip(&record.dst_ip), record.dst_port)
        };

        (record.id, record.name, dst_ip, dst_port, record.query_type)
    }

    #[cfg(test)]
    pub(super) fn response_identity_from_query(&self, query: &DnsQuery) -> ResponseIdentityKey {
        (
            query.id,
            query.name,
            query.src_ip,
            query.src_port,
            query.query_type,
        )
    }

    fn timeline_key_from_record(&self, record: &ProcessedDnsRecord) -> TimelineKey {
        TimelineKey::new(
            record.timestamp_micros,
            record.packet_ordinal,
            record.record_ordinal,
        )
    }

    pub(super) fn process_shard_records_with_batch_watermark(
        &self,
        shard_records: Vec<ProcessedDnsRecord>,
        state: &mut MatcherShardState,
        batch_max_timestamp_micros: Option<i64>,
    ) -> ShardProcessingResult {
        let mut max_timestamp_micros = None;
        let mut result = ShardProcessingResult {
            output_records: Vec::with_capacity(shard_records.len()),
            ..ShardProcessingResult::default()
        };

        for record in shard_records {
            max_timestamp_micros = Some(
                max_timestamp_micros.map_or(record.timestamp_micros, |current_max: i64| {
                    current_max.max(record.timestamp_micros)
                }),
            );
            if !record.is_query {
                self.process_response(
                    &record,
                    state,
                    &mut result.output_records,
                    &mut result.dns_response_count,
                    &mut result.matched_query_response_count,
                    &mut result.matched_rtt_sum_micros,
                );
            } else {
                self.process_query(
                    &record,
                    state,
                    &mut result.output_records,
                    &mut result.dns_query_count,
                    &mut result.duplicated_query_count,
                    &mut result.matched_query_response_count,
                    &mut result.matched_rtt_sum_micros,
                );
            }
        }

        if self.monotonic_capture
            && let Some(max_timestamp_micros) = batch_max_timestamp_micros.or(max_timestamp_micros)
        {
            self.apply_batched_timeout_eviction(
                max_timestamp_micros,
                state,
                &mut result.output_records,
                &mut result.timeout_query_count,
            );
        }

        result
    }

    pub(super) fn finalize_shard(&self, state: &mut MatcherShardState) -> ShardProcessingResult {
        let mut result = ShardProcessingResult::default();

        self.process_remaining_queries(
            state,
            &mut result.output_records,
            &mut result.matched_query_response_count,
            &mut result.timeout_query_count,
            &mut result.matched_rtt_sum_micros,
            &mut result.out_of_order_combined_count,
        );

        result
    }
}
