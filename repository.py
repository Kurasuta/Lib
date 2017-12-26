from .sample import SampleFactory, Sample


class SampleRepository(object):
    def __init__(self, db, allowed_source_identifiers):
        self.db = db
        self.factory = SampleFactory()

        with self.db.cursor() as cursor:
            cursor.execute(
                'SELECT id FROM sample_source WHERE (identifier IN %s)',
                (tuple(allowed_source_identifiers),)
            )
            self.allowed_source_ids = tuple([int(row[0]) for row in cursor.fetchall()])
            if len(self.allowed_source_ids) != len(allowed_source_identifiers):
                raise Exception('At least one source identifier is missing in database')

    def by_section_hash(self, sha256):
        with self.db.cursor() as cursor:
            cursor.execute('''
                SELECT sample.hash_sha256
                FROM section
                LEFT JOIN sample ON (sample.id = section.sample_id)
                LFET JOIN sample_has_source ON (sample.id = sample_has_source.sample_id)
                WHERE (section.hash_sha256 = %s) AND (sample_has_source.source_id in %s)
            ''', (sha256, self.allowed_source_ids))
            ret = []
            for row in cursor.fetchall():
                sample = Sample()
                sample.hash_sha256 = row[0]
                ret.append(sample)
            return ret

    def by_hash_sha256(self, sha256):
        with self.db.cursor() as cursor:
            cursor.execute('''
                SELECT
                    sample.id,
                    sample.hash_sha256,
                    sample.hash_md5,
                    sample.hash_sha1,
                    sample.size,
                    sample.ssdeep,
                    sample.imphash,
                    sample.entropy,
                    sample.file_size,
                    sample.entry_point,
                    sample.overlay_sha256,
                    sample.overlay_size,
                    sample.overlay_ssdeep,
                    sample.overlay_entropy,
                    sample.build_timestamp,
                    sample.strings_count_of_length_at_least_10,
                    sample.strings_count
                FROM sample
                LEFT JOIN sample_has_source ON (sample.id = sample_has_source.sample_id)
                WHERE (sample.hash_sha256 = %s) AND (sample_has_source.source_id IN %s)
            ''', (sha256, self.allowed_source_ids))

            # TODO join more tables and propagate to sample object

            sample = Sample()
            row = cursor.fetchone()
            if not row:
                return None
            sample_id, sample.hash_sha256, sample.hash_md5, sample.hash_sha1, sample.size, sample.ssdeep, sample.imphash, \
            sample.entropy, sample.file_size, sample.entry_point, sample.overlay_sha256, sample.overlay_size, \
            sample.overlay_ssdeep, sample.overlay_entropy, sample.build_timestamp, \
            sample.strings_count_of_length_at_least_10, sample.strings_count = row

            cursor.execute('''
                SELECT
                    s.hash_sha256,
                    sn.content AS name,
                    s.virtual_address,
                    s.virtual_size,
                    s.raw_size,
                    s.entropy,
                    s.ssdeep
                FROM section s
                LEFT JOIN section_name sn ON (s.name_id = sn.id)
                WHERE (s.sample_id = %s)
                ORDER BY s.sort_order
            ''', (sample_id,))
            for row in cursor.fetchall():
                sample.sections.append(self.factory.create_section(*row))

            return sample
