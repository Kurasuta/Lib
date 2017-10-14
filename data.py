from dateutil import parser as date_parser


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
        self.imports = None

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


class SampleFactory(object):
    @staticmethod
    def create_export(address, name, ordinal):
        export = SampleExport()
        export.address = address
        export.name = name
        export.ordinal = ordinal
        return export

    @staticmethod
    def create_import(dll_name, address, name):
        sample_import = SampleImport()
        sample_import.dll_name = dll_name
        sample_import.address = address
        sample_import.name = name
        return sample_import

    @staticmethod
    def create_section(hash_sha256, name, virtual_address, virtual_size, raw_size, entropy, ssdeep):
        section = SampleSection()
        section.hash_sha256 = hash_sha256
        section.name = name
        section.virtual_address = virtual_address
        section.virtual_size = virtual_size
        section.raw_size = raw_size
        section.entropy = entropy
        section.ssdeep = ssdeep
        return section

    @staticmethod
    def create_resource(
            hash_sha256, offset, size, actual_size, ssdeep, entropy, type_id, type_str, name_id, name_str, language_id,
            language_str
    ):
        resource = SampleResource()
        resource.hash_sha256 = hash_sha256
        resource.offset = offset
        resource.size = size
        resource.actual_size = actual_size
        resource.ssdeep = ssdeep
        resource.entropy = entropy
        resource.type_id = type_id
        resource.type_str = type_str
        resource.name_id = name_id
        resource.name_str = name_str
        resource.language_id = language_id
        resource.language_str = language_str
        return resource

    def from_json(self, d):
        sample = Sample()
        if 'hash_sha256' in d.keys(): sample.hash_sha256 = d['hash_sha256']
        if 'hash_md5' in d.keys(): sample.hash_md5 = d['hash_md5']
        if 'hash_sha1' in d.keys(): sample.hash_sha1 = d['hash_sha1']
        if 'size' in d.keys(): sample.size = int(d['size'])
        if 'code_histogram' in d.keys(): sample.code_histogram = d['code_histogram']

        if 'ssdeep' in d.keys(): sample.ssdeep = d['ssdeep']
        if 'entropy' in d.keys(): sample.entropy = float(d['entropy'])

        if 'file_size' in d.keys(): sample.file_size = int(d['file_size'])
        if 'entry_point' in d.keys(): sample.entry_point = d['entry_point']
        if 'first_kb' in d.keys(): sample.first_kb = d['first_kb']

        if 'overlay_sha256' in d.keys(): sample.overlay_sha256 = d['overlay_sha256']
        if 'overlay_size' in d.keys(): sample.overlay_size = int(d['overlay_size'])
        if 'overlay_ssdeep' in d.keys(): sample.overlay_ssdeep = d['overlay_ssdeep']
        if 'overlay_entropy' in d.keys(): sample.overlay_entropy = float(d['overlay_entropy'])

        if 'build_timestamp' in d.keys(): sample.build_timestamp = date_parser.parse(d['build_timestamp'])

        if 'debug_directory_count' in d.keys(): sample.debug_directory_count = int(d['debug_directory_count'])
        if 'debug_timestamp' in d.keys(): sample.debug_timestamp = date_parser.parse(d['debug_timestamp'])
        if 'pdb_timestamp' in d.keys(): sample.pdb_timestamp = date_parser.parse(d['pdb_timestamp'])
        if 'pdb_path' in d.keys(): sample.pdb_path = d['pdb_path']
        if 'pdb_guid' in d.keys(): sample.pdb_guid = d['pdb_guid']
        if 'pdb_age' in d.keys(): sample.pdb_age = d['pdb_age']
        if 'pdb_signature' in d.keys(): sample.pdb_signature = d['pdb_signature']

        if 'strings_count_of_length_at_least_10' in d.keys():
            sample.strings_count_of_length_at_least_10 = int(d['strings_count_of_length_at_least_10'])
        if 'strings_count' in d.keys(): sample.strings_count = int(d['strings_count'])
        if 'heuristic_iocs' in d.keys(): sample.heuristic_iocs = d['heuristic_iocs']

        if 'export_name' in d.keys(): sample.export_name = d['export_name']
        if 'exports' in d.keys():
            sample.exports = [
                self.create_export(export['address'], export['name'], export['ordinal'])
                for export in d['exports']
            ]
        if 'imports' in d.keys():
            sample.imports = [
                self.create_import(sample_import['dll_name'], sample_import['address'], sample_import['name'])
                for sample_import in d['imports']
            ]

        if 'sections' in d.keys():
            sample.sections = [
                self.create_section(
                    section['hash_sha256'], section['name'], section['virtual_address'],
                    section['virtual_size'], section['raw_size'], section['entropy'], section['ssdeep'],
                )
                for section in d['sections']
            ]

        if 'resources' in d.keys():
            sample.resources = [
                self.create_resource(
                    resource['hash_sha256'], resource['offset'], resource['size'], resource['actual_size'],
                    resource['ssdeep'], resource['entropy'], resource['type_id'], resource['type_str'],
                    resource['name_id'], resource['name_str'], resource['language_id'], resource['language_str']
                )
                for resource in d['resources']
            ]


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

        if sample.debug_directory_count is not None:
            d['debug_directory_count'] = self._format_int(sample.debug_directory_count)
        if sample.debug_timestamp is not None: d['debug_timestamp'] = self._format_timestamp(sample.debug_timestamp)
        if sample.pdb_timestamp is not None: d['pdb_timestamp'] = self._format_timestamp(sample.pdb_timestamp)
        if sample.pdb_path is not None: d['pdb_path'] = sample.pdb_path
        if sample.pdb_guid is not None: d['pdb_guid'] = sample.pdb_guid
        if sample.pdb_age is not None: d['pdb_age'] = sample.pdb_age
        if sample.pdb_signature is not None: d['pdb_signature'] = sample.pdb_signature

        if sample.strings_count_of_length_at_least_10 is not None:
            d['strings_count_of_length_at_least_10'] = self._format_int(sample.strings_count_of_length_at_least_10)
        if sample.strings_count is not None: d['strings_count'] = self._format_int(sample.strings_count)
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
