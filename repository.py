from .sample import SampleFactory, Sample
import random


class PostgresRepository(object):
    def __init__(self, db):
        self.db = db

    def approx_count(self, table):
        with self.db.cursor() as cursor:
            cursor.execute('SELECT reltuples AS approximate_row_count FROM pg_class WHERE (relname = %s)', (table,))
            return cursor.fetchall()[0][0]


class SampleRepository(PostgresRepository):
    def __init__(self, db, allowed_source_identifiers):
        super().__init__(db)
        self.factory = SampleFactory()

        with self.db.cursor() as cursor:
            cursor.execute(
                'SELECT id, identifier FROM sample_source WHERE (identifier IN %s)',
                (tuple(allowed_source_identifiers),)
            )
            result = [(int(row[0]), row[1]) for row in cursor.fetchall()]
            self.allowed_source_ids = tuple([row[0] for row in result])
            if len(self.allowed_source_ids) != len(allowed_source_identifiers):
                raise Exception(
                    'Found %s when queried for source identifiers %s' % (result, allowed_source_identifiers)
                )

    def by_section_hash(self, sha256):
        with self.db.cursor() as cursor:
            cursor.execute('''
                SELECT sample.hash_sha256, sample.build_timestamp
                FROM section
                LEFT JOIN sample ON (sample.id = section.sample_id)
                LEFT JOIN sample_has_source ON (sample.id = sample_has_source.sample_id)
                WHERE (section.hash_sha256 = %s) AND (sample_has_source.source_id in %s)
            ''', (sha256, self.allowed_source_ids))
            ret = []
            for row in cursor.fetchall():
                sample = Sample()
                sample.hash_sha256 = row[0]
                sample.build_timestamp = row[1]
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

    def newest(self, count):
        with self.db.cursor() as cursor:
            cursor.execute('''
                SELECT s.hash_sha256, s.build_timestamp 
                FROM sample s
                LEFT JOIN sample_has_source x ON (s.id = x.sample_id)
                WHERE (x.source_id IN %s)  
                ORDER BY s.id DESC 
                LIMIT %s
            ''', (self.allowed_source_ids, count))
            ret = []
            for row in cursor.fetchall():
                sample = Sample()
                sample.hash_sha256 = row[0]
                sample.build_timestamp = row[1]
                ret.append(sample)
            return ret

    def random(self, output_count):
        with self.db.cursor() as cursor:
            approximate_row_count = self.approx_count('sample')
            ret = []
            while len(ret) < output_count:
                rand = random.randint(0, approximate_row_count)
                cursor.execute('''
                    SELECT hash_sha256, build_timestamp
                    FROM sample
                    LEFT JOIN sample_has_source ON (sample.id = sample_has_source.sample_id)
                    WHERE (sample_has_source.source_id IN %s)
                    LIMIT 1 OFFSET %s
                ''', (self.allowed_source_ids, rand))
                rows = cursor.fetchall()
                if len(rows) == 0:
                    continue
                sample = Sample()
                sample.hash_sha256 = rows[0][0]
                sample.build_timestamp = rows[0][1]
                ret.append(sample)
            return ret
