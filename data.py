class FrozenClass(object):
    __isfrozen = False

    def __setattr__(self, key, value):
        if self.__isfrozen and not hasattr(self, key):
            raise TypeError('%r is a frozen class, cannot set "%s" to "%s"' % (self, key, value))
        object.__setattr__(self, key, value)

    def _freeze(self):
        self.__isfrozen = True


class Sample(FrozenClass):
    def __init__(self):
        self.hash_sha256 = None
        self.hash_md5 = None
        self.hash_sha1 = None
        self.size = None

        self.ssdeep = None
        self.entropy = None

        self.magic_id = None
        self.file_size = None
        self.entry_point = None
        self.first_kb = None
        self.overlay_sha256 = None
        self.overlay_size = None
        self.overlay_ssdeep = None
        self.overlay_entropy = None
        self.build_timestamp = None

        self.debug_directory_count = None
        self.debug_timestamp = None
        self.pdb_timestamp = None
        self.pdb_path = None
        self.pdb_guid = None
        self.pdb_age = None
        self.pdb_signature = None

        self.export_name = None
        self.exports = None
        self.export_table_timestamp = None
        self.imports = None
        self.resource_timestamp = None
        self.certificate_signing_timestamp = None

        self.strings_count_of_length_at_least_10 = None
        self.strings_count = None
        self.heuristic_iocs = None

        self.sections = []
        self.resources = []
        self.code_histogram = None

        self._freeze()

    def __repr__(self):
        return '<Sample %s,%s,%s>' % (self.hash_sha256, self.hash_md5, self.hash_sha1)


class SampleSection(FrozenClass):
    def __init__(self):
        self.hash_sha256 = None
        self.virtual_address = None
        self.virtual_size = None
        self.raw_size = None
        self.name = None

        self.entropy = None
        self.ssdeep = None

        self._freeze()

    def __repr__(self):
        return '<Section %s,%s,%s,%s,%s>' % (
            self.hash_sha256,
            self.virtual_address,
            self.virtual_size,
            self.raw_size,
            self.name
        )


class SampleResource(FrozenClass):
    def __init__(self):
        self.hash_sha256 = None
        self.offset = None
        self.size = None
        self.actual_size = None
        self.ssdeep = None
        self.entropy = None

        self.type_id = None
        self.type_str = None
        self.name_id = None
        self.name_str = None
        self.language_id = None
        self.language_str = None

        self._freeze()

    def __repr__(self):
        return '<Resource %s offset=%s,size=%s,actual_size=%s,type=%s:%s,name=%s:%s,language=%s:%s>' % (
            self.hash_sha256,
            self.offset,
            self.size,
            self.actual_size,
            self.type_id, self.type_str,
            self.name_id, self.name_str,
            self.language_id, self.language_str
        )


class SampleExport(FrozenClass):
    def __init__(self):
        self.address = None
        self.name = None
        self.ordinal = None
        self._freeze()


class SampleImport(FrozenClass):
    def __init__(self):
        self.dll_name = None
        self.address = None
        self.name = None
        self._freeze()


class JsonFactory(object):
    def __init__(self, filter=None):
        self.filter = filter

    @staticmethod
    def _format_int(data):
        return '%i' % data

    @staticmethod
    def _format_hex(data):
        return '0x%08x' % data

    @staticmethod
    def _format_float(data):
        return '%f' % data

    @staticmethod
    def _format_timestamp(data):
        return '%s' % data  # TODO

    @staticmethod
    def _format_pefile_unicode_wrapper(data):
        return '%s' % data

    def from_sample(self, sample):
        # TODO magic_id
        d = {}
        if sample.hash_sha256 is not None: d['hash_sha256'] = sample.hash_sha256
        if sample.hash_md5 is not None: d['hash_md5'] = sample.hash_md5
        if sample.hash_sha1 is not None: d['hash_sha1'] = sample.hash_sha1
        if sample.size is not None: d['size'] = self._format_int(sample.size)
        if sample.code_histogram is not None: d['code_histogram'] = sample.code_histogram

        if sample.ssdeep is not None: d['ssdeep'] = sample.ssdeep
        if sample.entropy is not None: d['entropy'] = self._format_float(sample.entropy)

        if sample.file_size is not None: d['file_size'] = self._format_int(sample.file_size)
        if sample.entry_point is not None: d['entry_point'] = self._format_hex(sample.entry_point)
        if sample.first_kb is not None: d['first_kb'] = sample.first_kb

        if sample.overlay_sha256 is not None: d['overlay_sha256'] = sample.overlay_sha256
        if sample.overlay_size is not None: d['overlay_size'] = self._format_int(sample.overlay_size)
        if sample.overlay_ssdeep is not None: d['overlay_ssdeep'] = sample.overlay_ssdeep
        if sample.overlay_entropy is not None: d['overlay_entropy'] = self._format_float(sample.overlay_entropy)

        if sample.build_timestamp is not None: d['build_timestamp'] = self._format_timestamp(sample.build_timestamp)

        if sample.debug_directory_count is not None: d['debug_directory_count'] = sample.debug_directory_count
        if sample.debug_timestamp is not None: d['debug_timestamp'] = self._format_timestamp(sample.debug_timestamp)
        if sample.pdb_timestamp is not None: d['pdb_timestamp'] = self._format_timestamp(sample.pdb_timestamp)
        if sample.pdb_path is not None: d['pdb_path'] = sample.pdb_path
        if sample.pdb_guid is not None: d['pdb_guid'] = sample.pdb_guid
        if sample.pdb_age is not None: d['pdb_age'] = sample.pdb_age
        if sample.pdb_signature is not None: d['pdb_signature'] = sample.pdb_signature

        if sample.strings_count_of_length_at_least_10 is not None:
            d['strings_count_of_length_at_least_10'] = sample.strings_count_of_length_at_least_10
        if sample.strings_count is not None: d['strings_count'] = sample.strings_count
        if sample.heuristic_iocs is not None: d['heuristic_iocs'] = sample.heuristic_iocs

        if sample.export_name is not None: d['export_name'] = sample.export_name
        if sample.exports:
            d['exports'] = [
                {'address': export.address, 'name': export.name, 'ordinal': export.ordinal}
                for export in sample.exports
            ]
        if sample.imports:
            d['imports'] = [
                {'dll_name': export.dll_name, 'address': export.address, 'name': export.name}
                for export in sample.imports
            ]

        if sample.export_table_timestamp is not None: d['export_table_timestamp'] = sample.export_table_timestamp
        if sample.resource_timestamp is not None:
            d['resource_timestamp'] = self._format_timestamp(sample.resource_timestamp)
        if sample.certificate_signing_timestamp is not None:
            d['certificate_signing_timestamp'] = self._format_timestamp(sample.certificate_signing_timestamp)

        if sample.sections:
            d['sections'] = [
                {
                    'hash_sha256': section.hash_sha256,
                    'name': section.name,
                    'virtual_address': section.virtual_address,
                    'virtual_size': section.virtual_size,
                    'raw_size': section.raw_size,
                    'entropy': section.entropy,
                    'ssdeep': section.ssdeep,
                } for section in sample.sections
            ]

        if sample.resources:
            d['resources'] = []
            for sample_resource in sample.resources:
                json_resource = {
                    'hash_sha256': sample_resource.hash_sha256,
                    'offset': sample_resource.offset,
                    'size': sample_resource.size,
                    'actual_size': sample_resource.actual_size,
                    'ssdeep': sample_resource.ssdeep,
                    'entropy': sample_resource.entropy,
                }
                if sample_resource.type_id: json_resource['type_id'] = sample_resource.type_id
                if sample_resource.type_str: json_resource['type_str'] = \
                    '%s' % self._format_pefile_unicode_wrapper(sample_resource.type_str)
                if sample_resource.name_id: json_resource['name_id'] = sample_resource.name_id
                if sample_resource.name_str: json_resource['name_str'] = \
                    '%s' % self._format_pefile_unicode_wrapper(sample_resource.name_str)
                if sample_resource.language_id: json_resource['language_id'] = sample_resource.language_id
                if sample_resource.language_str: json_resource['language_str'] = \
                    '%s' % self._format_pefile_unicode_wrapper(sample_resource.language_str)

                d['resources'].append(json_resource)

        if self.filter:
            d = {k: v for k, v in d.items() if self.filter in k}
        return d
