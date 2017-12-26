from sample import SampleFactory, Sample


class SampleRepository(object):
    def __init__(self, db):
        self.db = db
        self.factory = SampleFactory()

    def by_hash_sha256(self, sha256):
        with self.db.cursor() as cursor:
            cursor.execute('''
                SELECT
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
                WHERE (sample.hash_sha256 = %s)
            ''', sha256)

            # TODO join more tables and propagate to sample object

            sample = Sample()
            row = cursor.fetchone()
            sample.hash_sha256 = row[0]
            sample.hash_md5 = row[1]
            sample.hash_sha1 = row[2]
            sample.size = row[3]
            sample.ssdeep = row[4]
            sample.imphash = row[5]
            sample.entropy = row[6]
            sample.file_size = row[7]
            sample.entry_point = row[8]
            sample.overlay_sha256 = row[9]
            sample.overlay_size = row[10]
            sample.overlay_ssdeep = row[11]
            sample.overlay_entropy = row[12]
            sample.build_timestamp = row[13]
            sample.strings_count_of_length_at_least_10 = row[14]
            sample.strings_count = row[15]

            return sample
