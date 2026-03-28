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
    DnsQuery, DnsResponse, MAX_RECORD_DISCRIMINATOR, MIN_RECORD_DISCRIMINATOR, ProcessedDnsRecord,
    QueryIdentityKey, QueryKey, QueryMap, RecordDiscriminator, ResponseIdentityKey, ResponseKey,
    ResponseMap, ShardProcessingResult,
};
use crate::custom_types::{ProtoRecordType, ProtoResponseCode};
use crate::record::DnsRecord;

impl DnsProcessor {
    fn collect_timeline_records<Identity, Record>(
        map: &BTreeMap<Identity, BTreeMap<i64, BTreeMap<RecordDiscriminator, Record>>>,
    ) -> Vec<Record>
    where
        Record: Clone,
    {
        let mut records = Vec::new();
        for timeline in map.values() {
            for bucket in timeline.values() {
                records.extend(bucket.values().cloned());
            }
        }
        records
    }

    fn remove_timeline_entry<Identity, Record>(
        map: &mut BTreeMap<Identity, BTreeMap<i64, BTreeMap<RecordDiscriminator, Record>>>,
        identity: Identity,
        timestamp: i64,
        discriminator: RecordDiscriminator,
    ) -> Option<Record>
    where
        Identity: Ord,
    {
        let mut remove_identity = false;

        let removed = if let Some(timeline) = map.get_mut(&identity) {
            let removed = timeline
                .get_mut(&timestamp)
                .and_then(|bucket| bucket.remove(&discriminator));

            if timeline
                .get(&timestamp)
                .is_some_and(std::collections::BTreeMap::is_empty)
            {
                timeline.remove(&timestamp);
            }

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
            name: query.name.into(),
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
            name: query.name.into(),
            query_type: ProtoRecordType::from(query.query_type),
            response_code: ProtoResponseCode::from(HickoryResponseCode::ServFail),
        }
    }

    fn has_pending_query_before(&self, query_map: &QueryMap, query: &DnsQuery) -> bool {
        let identity = self.query_identity_key(query);
        let Some(timeline) = query_map.get(&identity) else {
            return false;
        };

        timeline
            .range(
                query
                    .timestamp_micros
                    .saturating_sub(self.match_timeout_micros)
                    ..=query.timestamp_micros,
            )
            .next()
            .is_some()
    }

    fn process_query(
        &self,
        record: &ProcessedDnsRecord,
        query_map: &mut QueryMap,
        response_map: &mut ResponseMap,
        output_records: &mut Vec<DnsRecord>,
        dns_query_count: &mut usize,
        duplicated_query_count: &mut usize,
        matched_query_response_count: &mut usize,
        matched_rtt_sum_micros: &mut u64,
    ) {
        let query = self.create_dns_query(record);
        *dns_query_count += 1;

        if self.has_pending_query_before(query_map, &query) {
            *duplicated_query_count += 1;
            return;
        }

        let lower_bound_key = self.create_response_key_from_query(
            &query,
            query.timestamp_micros,
            MIN_RECORD_DISCRIMINATOR.0,
            MIN_RECORD_DISCRIMINATOR.1,
        );
        let upper_bound_key = self.create_response_key_from_query(
            &query,
            query
                .timestamp_micros
                .saturating_add(self.match_timeout_micros),
            MAX_RECORD_DISCRIMINATOR.0,
            MAX_RECORD_DISCRIMINATOR.1,
        );

        if let Some((_, response, _)) = self.find_closest_response(
            response_map,
            &lower_bound_key,
            &upper_bound_key,
            query.timestamp_micros,
        ) {
            self.remove_response_and_collect_matched_record(
                output_records,
                &query,
                &response,
                response_map,
                matched_query_response_count,
                matched_rtt_sum_micros,
            );
        } else {
            self.insert_query_entry(query_map, query);
        }
    }

    fn process_response(
        &self,
        record: &ProcessedDnsRecord,
        query_map: &mut QueryMap,
        response_map: &mut ResponseMap,
        output_records: &mut Vec<DnsRecord>,
        dns_response_count: &mut usize,
        matched_query_response_count: &mut usize,
        matched_rtt_sum_micros: &mut u64,
    ) {
        let response = self.create_dns_response(record);
        *dns_response_count += 1;

        let lower_bound_key = self.create_query_key_from_response(
            &response,
            response
                .timestamp_micros
                .saturating_sub(self.match_timeout_micros),
            MIN_RECORD_DISCRIMINATOR.0,
            MIN_RECORD_DISCRIMINATOR.1,
        );
        let upper_bound_key = self.create_query_key_from_response(
            &response,
            response.timestamp_micros,
            MAX_RECORD_DISCRIMINATOR.0,
            MAX_RECORD_DISCRIMINATOR.1,
        );

        if let Some((_, query, _)) = self.find_closest_query(
            query_map,
            &lower_bound_key,
            &upper_bound_key,
            response.timestamp_micros,
        ) {
            self.remove_query_and_collect_matched_record(
                output_records,
                &query,
                &response,
                query_map,
                matched_query_response_count,
                matched_rtt_sum_micros,
            );
        } else {
            self.insert_response_entry(response_map, response);
        }
    }

    fn process_remaining_queries(
        &self,
        query_map: &mut QueryMap,
        response_map: &mut ResponseMap,
        output_records: &mut Vec<DnsRecord>,
        matched_query_response_count: &mut usize,
        timeout_query_count: &mut usize,
        matched_rtt_sum_micros: &mut u64,
        out_of_order_combined_count: &mut usize,
    ) {
        let remaining_queries = self.collect_queries(query_map);

        for query in remaining_queries {
            let query_timestamp = query.timestamp_micros;

            let lower_bound_key =
                self.create_response_key_from_query(&query, query_timestamp, u64::MIN, u32::MIN);
            let upper_bound_key = self.create_response_key_from_query(
                &query,
                query_timestamp.saturating_add(self.match_timeout_micros),
                u64::MAX,
                u32::MAX,
            );

            if let Some((_, response, _)) = self.find_closest_response(
                response_map,
                &lower_bound_key,
                &upper_bound_key,
                query_timestamp,
            ) {
                self.remove_response_and_collect_matched_record(
                    output_records,
                    &query,
                    &response,
                    response_map,
                    matched_query_response_count,
                    matched_rtt_sum_micros,
                );
                self.remove_query_entry(query_map, &query);
                *out_of_order_combined_count += 1;
            } else {
                output_records.push(DnsProcessor::create_timeout_record(&query));
                self.remove_query_entry(query_map, &query);
                *timeout_query_count += 1;
            }
        }
    }

    fn evict_queries_before(
        &self,
        query_map: &mut QueryMap,
        threshold_timestamp_micros: i64,
        output_records: &mut Vec<DnsRecord>,
        timeout_query_count: &mut usize,
    ) {
        query_map.retain(|_, timeline| {
            while timeline
                .first_key_value()
                .is_some_and(|(&timestamp_micros, _)| timestamp_micros < threshold_timestamp_micros)
            {
                let (_, bucket) = timeline
                    .pop_first()
                    .expect("timeline must have first bucket");
                for query in bucket.into_values() {
                    output_records.push(DnsProcessor::create_timeout_record(&query));
                    *timeout_query_count += 1;
                }
            }

            !timeline.is_empty()
        });
    }

    fn evict_responses_before(
        &self,
        response_map: &mut ResponseMap,
        threshold_timestamp_micros: i64,
    ) {
        response_map.retain(|_, timeline| {
            while timeline
                .first_key_value()
                .is_some_and(|(&timestamp_micros, _)| timestamp_micros < threshold_timestamp_micros)
            {
                timeline.pop_first();
            }

            !timeline.is_empty()
        });
    }

    fn apply_batched_timeout_eviction(
        &self,
        max_timestamp_micros: i64,
        query_map: &mut QueryMap,
        response_map: &mut ResponseMap,
        output_records: &mut Vec<DnsRecord>,
        timeout_query_count: &mut usize,
    ) {
        let threshold_timestamp_micros =
            max_timestamp_micros.saturating_sub(self.match_timeout_micros);

        self.evict_queries_before(
            query_map,
            threshold_timestamp_micros,
            output_records,
            timeout_query_count,
        );
        self.evict_responses_before(response_map, threshold_timestamp_micros);
    }

    pub(super) fn create_query_key_from_response(
        &self,
        response: &DnsResponse,
        timestamp: i64,
        packet_ordinal: u64,
        record_ordinal: u32,
    ) -> QueryKey {
        (
            response.id,
            response.name,
            response.dst_ip,
            response.dst_port,
            response.query_type,
            timestamp,
            packet_ordinal,
            record_ordinal,
        )
    }

    pub(super) fn insert_query_entry(&self, query_map: &mut QueryMap, query: DnsQuery) {
        query_map
            .entry(self.query_identity_key(&query))
            .or_default()
            .entry(query.timestamp_micros)
            .or_default()
            .insert((query.packet_ordinal, query.record_ordinal), query);
    }

    pub(super) fn insert_response_entry(
        &self,
        response_map: &mut ResponseMap,
        response: DnsResponse,
    ) {
        response_map
            .entry(self.response_identity_key(&response))
            .or_default()
            .entry(response.timestamp_micros)
            .or_default()
            .insert((response.packet_ordinal, response.record_ordinal), response);
    }

    fn collect_queries(&self, query_map: &QueryMap) -> Vec<DnsQuery> {
        Self::collect_timeline_records(query_map)
    }

    fn remove_query_entry(&self, query_map: &mut QueryMap, query: &DnsQuery) -> Option<DnsQuery> {
        Self::remove_timeline_entry(
            query_map,
            self.query_identity_key(query),
            query.timestamp_micros,
            (query.packet_ordinal, query.record_ordinal),
        )
    }

    fn remove_response_entry(
        &self,
        response_map: &mut ResponseMap,
        response: &DnsResponse,
    ) -> Option<DnsResponse> {
        Self::remove_timeline_entry(
            response_map,
            self.response_identity_key(response),
            response.timestamp_micros,
            (response.packet_ordinal, response.record_ordinal),
        )
    }

    fn remove_query_and_collect_matched_record(
        &self,
        output_records: &mut Vec<DnsRecord>,
        query: &DnsQuery,
        response: &DnsResponse,
        query_map: &mut QueryMap,
        matched_query_response_count: &mut usize,
        matched_rtt_sum_micros: &mut u64,
    ) {
        self.remove_query_entry(query_map, query);
        output_records.push(DnsProcessor::create_matched_record(query, response));
        *matched_query_response_count += 1;
        // Saturating subtraction still permits a negative RTT when response timestamps regress
        // relative to the matched query, so clamp before casting to u64.
        *matched_rtt_sum_micros += response
            .timestamp_micros
            .saturating_sub(query.timestamp_micros)
            .max(0) as u64;
    }

    fn remove_response_and_collect_matched_record(
        &self,
        output_records: &mut Vec<DnsRecord>,
        query: &DnsQuery,
        response: &DnsResponse,
        response_map: &mut ResponseMap,
        matched_query_response_count: &mut usize,
        matched_rtt_sum_micros: &mut u64,
    ) {
        self.remove_response_entry(response_map, response);
        output_records.push(DnsProcessor::create_matched_record(query, response));
        *matched_query_response_count += 1;
        // Saturating subtraction still permits a negative RTT when response timestamps regress
        // relative to the matched query, so clamp before casting to u64.
        *matched_rtt_sum_micros += response
            .timestamp_micros
            .saturating_sub(query.timestamp_micros)
            .max(0) as u64;
    }

    pub(super) fn find_closest_response(
        &self,
        response_map: &ResponseMap,
        lower_bound_key: &ResponseKey,
        upper_bound_key: &ResponseKey,
        query_timestamp_micros: i64,
    ) -> Option<(i64, DnsResponse, ResponseKey)> {
        let identity = self.response_identity_from_key(upper_bound_key);
        let timeline = response_map.get(&identity)?;
        let (&response_timestamp, bucket) = timeline
            .range(lower_bound_key.5..=upper_bound_key.5)
            .next()?;
        let (&discriminator, response) = bucket.first_key_value()?;
        let time_diff = response_timestamp - query_timestamp_micros;

        Some((
            time_diff,
            response.clone(),
            self.create_response_key(
                response,
                response_timestamp,
                discriminator.0,
                discriminator.1,
            ),
        ))
    }

    pub(super) fn find_closest_query(
        &self,
        query_map: &QueryMap,
        lower_bound_key: &QueryKey,
        upper_bound_key: &QueryKey,
        response_timestamp_micros: i64,
    ) -> Option<(i64, DnsQuery, QueryKey)> {
        let identity = self.query_identity_from_key(upper_bound_key);
        let timeline = query_map.get(&identity)?;
        let (&query_timestamp, bucket) = timeline
            .range(lower_bound_key.5..=upper_bound_key.5)
            .next_back()?;
        let (&discriminator, query) = bucket.first_key_value()?;
        let time_diff = response_timestamp_micros.checked_sub(query_timestamp)?;

        Some((
            time_diff,
            query.clone(),
            self.create_query_key(query, query_timestamp, discriminator.0, discriminator.1),
        ))
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

    fn query_identity_from_key(&self, key: &QueryKey) -> QueryIdentityKey {
        (key.0, key.1, key.2, key.3, key.4)
    }

    fn response_identity_from_key(&self, key: &ResponseKey) -> ResponseIdentityKey {
        (key.0, key.1, key.2, key.3, key.4)
    }

    pub(super) fn create_query_key(
        &self,
        query: &DnsQuery,
        timestamp: i64,
        packet_ordinal: u64,
        record_ordinal: u32,
    ) -> QueryKey {
        (
            query.id,
            query.name,
            query.src_ip,
            query.src_port,
            query.query_type,
            timestamp,
            packet_ordinal,
            record_ordinal,
        )
    }

    pub(super) fn create_response_key(
        &self,
        response: &DnsResponse,
        timestamp: i64,
        packet_ordinal: u64,
        record_ordinal: u32,
    ) -> ResponseKey {
        (
            response.id,
            response.name,
            response.dst_ip,
            response.dst_port,
            response.query_type,
            timestamp,
            packet_ordinal,
            record_ordinal,
        )
    }

    pub(super) fn create_response_key_from_query(
        &self,
        query: &DnsQuery,
        timestamp: i64,
        packet_ordinal: u64,
        record_ordinal: u32,
    ) -> ResponseKey {
        (
            query.id,
            query.name,
            query.src_ip,
            query.src_port,
            query.query_type,
            timestamp,
            packet_ordinal,
            record_ordinal,
        )
    }

    pub(super) fn process_shard_records_with_batch_watermark(
        &self,
        shard_records: Vec<ProcessedDnsRecord>,
        query_map: &mut QueryMap,
        response_map: &mut ResponseMap,
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
                    query_map,
                    response_map,
                    &mut result.output_records,
                    &mut result.dns_response_count,
                    &mut result.matched_query_response_count,
                    &mut result.matched_rtt_sum_micros,
                );
            } else {
                self.process_query(
                    &record,
                    query_map,
                    response_map,
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
                query_map,
                response_map,
                &mut result.output_records,
                &mut result.timeout_query_count,
            );
        }

        result
    }

    pub(super) fn finalize_shard(
        &self,
        query_map: &mut QueryMap,
        response_map: &mut ResponseMap,
    ) -> ShardProcessingResult {
        let mut result = ShardProcessingResult::default();

        self.process_remaining_queries(
            query_map,
            response_map,
            &mut result.output_records,
            &mut result.matched_query_response_count,
            &mut result.timeout_query_count,
            &mut result.matched_rtt_sum_micros,
            &mut result.out_of_order_combined_count,
        );

        result
    }
}
