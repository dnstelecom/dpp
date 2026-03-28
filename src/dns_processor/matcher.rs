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
    DnsQuery, DnsResponse, EntryHandle, MatcherShardState, ProcessedDnsRecord, QueryIdentityKey,
    ResponseIdentityKey, ShardProcessingResult, Timeline, TimelineKey,
};
use crate::custom_types::{ProtoRecordType, ProtoResponseCode};
use crate::record::DnsRecord;

impl DnsProcessor {
    fn collect_timeline_records<Identity, Record>(
        map: &BTreeMap<Identity, Timeline<Record>>,
    ) -> Vec<Record>
    where
        Record: Clone,
    {
        let mut records = Vec::new();
        for timeline in map.values() {
            timeline.extend_cloned_into(&mut records);
        }
        records
    }

    fn remove_timeline_entry<Identity, Record>(
        map: &mut BTreeMap<Identity, Timeline<Record>>,
        identity: Identity,
        key: TimelineKey,
    ) -> Option<Record>
    where
        Identity: Ord,
    {
        let mut remove_identity = false;

        let removed = if let Some(timeline) = map.get_mut(&identity) {
            let removed = timeline.remove(key);
            remove_identity = timeline.is_empty();
            removed
        } else {
            None
        };

        if remove_identity {
            map.remove(&identity);
        }

        removed
    }

    fn create_matched_record(query: &DnsQuery, response: &DnsResponse) -> DnsRecord {
        DnsRecord {
            request_timestamp: query.timestamp_micros,
            response_timestamp: response.timestamp_micros,
            source_ip: query.src_ip,
            source_port: query.src_port,
            id: query.id,
            name: query.name,
            query_type: ProtoRecordType::from(query.query_type),
            response_code: ProtoResponseCode::from(response.response_code),
        }
    }

    fn create_timeout_record(query: &DnsQuery) -> DnsRecord {
        DnsRecord {
            request_timestamp: query.timestamp_micros,
            response_timestamp: 0,
            source_ip: query.src_ip,
            source_port: query.src_port,
            id: query.id,
            name: query.name,
            query_type: ProtoRecordType::from(query.query_type),
            response_code: ProtoResponseCode::from(HickoryResponseCode::ServFail),
        }
    }

    fn has_pending_query_before(&self, state: &MatcherShardState, query: &DnsQuery) -> bool {
        let identity = self.query_identity_key(query);
        let Some(timeline) = state.query_map.get(&identity) else {
            return false;
        };

        timeline.contains_timestamp_range(
            query
                .timestamp_micros
                .saturating_sub(self.match_timeout_micros),
            query.timestamp_micros,
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
        let query = self.create_dns_query(record);
        *dns_query_count += 1;

        if self.has_pending_query_before(state, &query) {
            *duplicated_query_count += 1;
            return;
        }

        let response_identity = self.response_identity_from_query(&query);

        if let Some((_, response_handle)) = self.find_closest_response(
            state,
            &response_identity,
            query.timestamp_micros,
            query
                .timestamp_micros
                .saturating_add(self.match_timeout_micros),
            query.timestamp_micros,
        ) {
            let response = self
                .remove_response_entry(state, response_handle)
                .expect("matched response handle must remain valid until removal");
            output_records.push(DnsProcessor::create_matched_record(&query, &response));
            *matched_query_response_count += 1;
            *matched_rtt_sum_micros += response
                .timestamp_micros
                .saturating_sub(query.timestamp_micros)
                .max(0) as u64;
        } else {
            self.insert_query_entry(state, query);
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
        let response = self.create_dns_response(record);
        *dns_response_count += 1;

        let query_identity = self.query_identity_from_response(&response);

        if let Some((_, query_handle)) = self.find_closest_query(
            state,
            &query_identity,
            response
                .timestamp_micros
                .saturating_sub(self.match_timeout_micros),
            response.timestamp_micros,
            response.timestamp_micros,
        ) {
            let query = self
                .remove_query_entry(state, query_handle)
                .expect("matched query handle must remain valid until removal");
            output_records.push(DnsProcessor::create_matched_record(&query, &response));
            *matched_query_response_count += 1;
            *matched_rtt_sum_micros += response
                .timestamp_micros
                .saturating_sub(query.timestamp_micros)
                .max(0) as u64;
        } else {
            self.insert_response_entry(state, response);
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
        let remaining_queries = self.collect_queries(state);

        for query_handle in remaining_queries {
            let query = state
                .query_arena
                .get(query_handle)
                .expect("query handle collected from timeline must remain valid");
            let query_timestamp = query.timestamp_micros;
            let response_identity = self.response_identity_from_query(query);

            if let Some((_, response_handle)) = self.find_closest_response(
                state,
                &response_identity,
                query_timestamp,
                query_timestamp.saturating_add(self.match_timeout_micros),
                query_timestamp,
            ) {
                let response = self
                    .remove_response_entry(state, response_handle)
                    .expect("matched response handle must remain valid until removal");
                let query = self
                    .remove_query_entry(state, query_handle)
                    .expect("pending query handle must remain valid until removal");
                output_records.push(DnsProcessor::create_matched_record(&query, &response));
                *matched_query_response_count += 1;
                *matched_rtt_sum_micros += response
                    .timestamp_micros
                    .saturating_sub(query.timestamp_micros)
                    .max(0) as u64;
                *out_of_order_combined_count += 1;
            } else {
                let query = self
                    .remove_query_entry(state, query_handle)
                    .expect("pending query handle must remain valid until removal");
                output_records.push(DnsProcessor::create_timeout_record(&query));
                *timeout_query_count += 1;
            }
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
        let query_arena = &mut state.query_arena;

        query_map.retain(|_, timeline| {
            timeline.drain_before(threshold_timestamp_micros, |handle| {
                let query = query_arena
                    .remove(handle)
                    .expect("evicted query handle must resolve in arena");
                output_records.push(DnsProcessor::create_timeout_record(&query));
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
        let response_arena = &mut state.response_arena;

        response_map.retain(|_, timeline| {
            timeline.drain_before(threshold_timestamp_micros, |handle| {
                let _ = response_arena
                    .remove(handle)
                    .expect("evicted response handle must resolve in arena");
            });
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

    pub(super) fn insert_query_entry(&self, state: &mut MatcherShardState, query: DnsQuery) {
        let identity = self.query_identity_key(&query);
        let timeline_key = self.timeline_key_for_query(&query);
        let handle = state.query_arena.alloc(query);

        let replaced = state
            .query_map
            .entry(identity)
            .or_default()
            .insert(timeline_key, handle);

        if let Some(replaced_handle) = replaced {
            let _ = state
                .query_arena
                .remove(replaced_handle)
                .expect("replaced query handle must resolve in arena");
            debug_assert!(
                false,
                "query timeline unexpectedly replaced an existing handle for identical identity/timeline key"
            );
        }
    }

    pub(super) fn insert_response_entry(
        &self,
        state: &mut MatcherShardState,
        response: DnsResponse,
    ) {
        let identity = self.response_identity_key(&response);
        let timeline_key = self.timeline_key_for_response(&response);
        let handle = state.response_arena.alloc(response);

        let replaced = state
            .response_map
            .entry(identity)
            .or_default()
            .insert(timeline_key, handle);

        if let Some(replaced_handle) = replaced {
            let _ = state
                .response_arena
                .remove(replaced_handle)
                .expect("replaced response handle must resolve in arena");
            debug_assert!(
                false,
                "response timeline unexpectedly replaced an existing handle for identical identity/timeline key"
            );
        }
    }

    fn collect_queries(&self, state: &MatcherShardState) -> Vec<EntryHandle> {
        Self::collect_timeline_records(&state.query_map)
    }

    fn remove_query_entry(
        &self,
        state: &mut MatcherShardState,
        handle: EntryHandle,
    ) -> Option<DnsQuery> {
        let query = state.query_arena.get(handle)?;
        let identity = self.query_identity_key(query);
        let timeline_key = self.timeline_key_for_query(query);
        let removed_handle =
            Self::remove_timeline_entry(&mut state.query_map, identity, timeline_key)?;
        debug_assert_eq!(removed_handle, handle);
        state.query_arena.remove(removed_handle)
    }

    fn remove_response_entry(
        &self,
        state: &mut MatcherShardState,
        handle: EntryHandle,
    ) -> Option<DnsResponse> {
        let response = state.response_arena.get(handle)?;
        let identity = self.response_identity_key(response);
        let timeline_key = self.timeline_key_for_response(response);
        let removed_handle =
            Self::remove_timeline_entry(&mut state.response_map, identity, timeline_key)?;
        debug_assert_eq!(removed_handle, handle);
        state.response_arena.remove(removed_handle)
    }

    pub(super) fn find_closest_response(
        &self,
        state: &MatcherShardState,
        response_identity: &ResponseIdentityKey,
        lower_timestamp_micros: i64,
        upper_timestamp_micros: i64,
        query_timestamp_micros: i64,
    ) -> Option<(i64, EntryHandle)> {
        let timeline = state.response_map.get(response_identity)?;
        let response_handle =
            *timeline.first_in_range(lower_timestamp_micros, upper_timestamp_micros)?;
        let response = state
            .response_arena
            .get(response_handle)
            .expect("response handle stored in timeline must resolve in arena");

        Some((
            response.timestamp_micros - query_timestamp_micros,
            response_handle,
        ))
    }

    pub(super) fn find_closest_query(
        &self,
        state: &MatcherShardState,
        query_identity: &QueryIdentityKey,
        lower_timestamp_micros: i64,
        upper_timestamp_micros: i64,
        response_timestamp_micros: i64,
    ) -> Option<(i64, EntryHandle)> {
        let timeline = state.query_map.get(query_identity)?;
        let query_handle =
            *timeline.last_in_range(lower_timestamp_micros, upper_timestamp_micros)?;
        let query = state
            .query_arena
            .get(query_handle)
            .expect("query handle stored in timeline must resolve in arena");
        let time_diff = response_timestamp_micros.checked_sub(query.timestamp_micros)?;

        Some((time_diff, query_handle))
    }

    fn create_dns_query(&self, record: &ProcessedDnsRecord) -> DnsQuery {
        DnsQuery {
            id: record.id,
            name: record.name,
            src_ip: self.anonymize_ip(&record.src_ip),
            src_port: record.src_port,
            timestamp_micros: record.timestamp_micros,
            packet_ordinal: record.packet_ordinal,
            record_ordinal: record.record_ordinal,
            query_type: record.query_type,
        }
    }

    fn create_dns_response(&self, record: &ProcessedDnsRecord) -> DnsResponse {
        DnsResponse {
            id: record.id,
            name: record.name,
            dst_ip: self.anonymize_ip(&record.dst_ip),
            dst_port: record.dst_port,
            timestamp_micros: record.timestamp_micros,
            packet_ordinal: record.packet_ordinal,
            record_ordinal: record.record_ordinal,
            response_code: record.response_code,
            query_type: record.query_type,
        }
    }

    fn query_identity_key(&self, query: &DnsQuery) -> QueryIdentityKey {
        (
            query.id,
            query.name,
            query.src_ip,
            query.src_port,
            query.query_type,
        )
    }

    fn response_identity_key(&self, response: &DnsResponse) -> ResponseIdentityKey {
        (
            response.id,
            response.name,
            response.dst_ip,
            response.dst_port,
            response.query_type,
        )
    }

    pub(super) fn query_identity_from_response(&self, response: &DnsResponse) -> QueryIdentityKey {
        (
            response.id,
            response.name,
            response.dst_ip,
            response.dst_port,
            response.query_type,
        )
    }

    pub(super) fn response_identity_from_query(&self, query: &DnsQuery) -> ResponseIdentityKey {
        (
            query.id,
            query.name,
            query.src_ip,
            query.src_port,
            query.query_type,
        )
    }

    fn timeline_key_for_query(&self, query: &DnsQuery) -> TimelineKey {
        TimelineKey::new(
            query.timestamp_micros,
            query.packet_ordinal,
            query.record_ordinal,
        )
    }

    fn timeline_key_for_response(&self, response: &DnsResponse) -> TimelineKey {
        TimelineKey::new(
            response.timestamp_micros,
            response.packet_ordinal,
            response.record_ordinal,
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
