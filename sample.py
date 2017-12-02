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
        self.hash_sha256 = None  # type: str
        self.hash_md5 = None  # type: str
        self.hash_sha1 = None  # type: str
        self.size = None  # type: int
        self.peyd = None  # type: list[str]
        self.magic = None  # type: str

        self.ssdeep = None  # type: str
        self.imphash = None  # type: str
        self.entropy = None  # type: float

        self.file_size = None  # type: int
        self.entry_point = None  # type: int
        self.first_kb = None  # type: bytearray
        self.overlay_sha256 = None  # type: str
        self.overlay_size = None  # type: int
        self.overlay_ssdeep = None  # type: str
        self.overlay_entropy = None  # type: float
        self.build_timestamp = None

        self.debug_directories = None  # type: list[SampleDebugDirectory]
        self.export_name = None  # type: str
        self.exports = None  # type: list[SampleExport]
        self.imports = None  # type: list[SampleImport]

        self.strings_count_of_length_at_least_10 = None  # type: int
        self.strings_count = None  # type: int
        self.heuristic_iocs = None  # type: list[str]

        self.sections = []  # type: list[SampleSection]
        self.resources = []  # type: list[SampleResource]

        self.functions = []  # type: list[SampleFunction]
        self.code_histogram = None

        self._freeze()

    def __repr__(self):
        return '<Sample %s,%s,%s>' % (self.hash_sha256, self.hash_md5, self.hash_sha1)


class SampleFunction(FrozenClass):
    def __init__(self):
        self.offset = None  # type: int
        self.size = None  # type: int
        self.real_size = None  # type: int
        self.name = None  # type: str

        self.calltype = None  # type: str
        self.cc = None  # type: int
        self.cost = None  # type: int
        self.ebbs = None  # type: int
        self.edges = None  # type: int
        self.indegree = None  # type: int
        self.nargs = None  # type: int
        self.nbbs = None  # type: int
        self.nlocals = None  # type: int
        self.outdegree = None  # type: int
        self.type = None  # type: str

        self.opcodes_sha256 = None  # type: str
        self.opcodes_crc32 = None  # type: str
        self.cleaned_opcodes_sha256 = None  # type: str
        self.cleaned_opcodes_crc32 = None  # type: str

        self.opcodes = None  # type: list

        self._freeze()


class SampleSection(FrozenClass):
    def __init__(self):
        self.hash_sha256 = None  # type: str
        self.virtual_address = None  # type: int
        self.virtual_size = None  # type: int
        self.raw_size = None  # type: int
        self.name = None  # type: str

        self.entropy = None  # type: float
        self.ssdeep = None  # type: str

        self._freeze()

    def __repr__(self):
        return '<Section %s,%s,%s,%s,%s>' % (
            self.hash_sha256,
            self.virtual_address,
            self.virtual_size,
            self.raw_size,
            self.name
        )


class SampleMeta(FrozenClass):
    def __init__(self):
        self.source_id = None  # type: None|int
        self.tags = []  # type: list[str]
        self.file_names = []  # type: list[str]

        self._freeze()

    def to_dict(self):
        data = {}
        if self.tags:
            data['tags'] = self.tags
        if self.file_names:
            data['file_names'] = self.file_names
        if self.source_id:
            data['source_id'] = self.source_id
        return data


class SampleResource(FrozenClass):
    def __init__(self):
        self.hash_sha256 = None  # type: str
        self.offset = None  # type: int
        self.size = None  # type: int
        self.actual_size = None  # type: int
        self.ssdeep = None  # type: str
        self.entropy = None  # type: float

        self.type_id = None  # type: str
        self.type_str = None  # type: str
        self.name_id = None  # type: str
        self.name_str = None  # type: str
        self.language_id = None  # type: str
        self.language_str = None  # type: str

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
        self.address = None  # type: int
        self.name = None  # type: str
        self.ordinal = None  # type: str
        self._freeze()


class SampleImport(FrozenClass):
    def __init__(self):
        self.dll_name = None  # type: str
        self.address = None  # type: int
        self.name = None  # type: str
        self._freeze()


class SampleDebugDirectory(FrozenClass):
    def __init__(self):
        self.timestamp = None
        self.path = None  # type: str
        self.age = None  # type: int
        self.signature = None  # type: str
        self.guid = None  # type: str
        self._freeze()

    def __repr__(self):
        return '<SampleDebugDirectory path=%s,age=%s,signature=%s,guid=%s>' % (
            self.path,
            self.age,
            self.signature,
            self.guid
        )


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

    @staticmethod
    def create_debug_directory(timestamp, path, age, signature, guid):
        debug_directory = SampleDebugDirectory()
        debug_directory.timestamp = timestamp
        debug_directory.path = path
        debug_directory.age = age
        debug_directory.signature = signature
        debug_directory.guid = guid
        return debug_directory

    @staticmethod
    def create_function(
            offset, size, real_size, name, calltype, cc, cost, ebbs, edges, indegree, nargs, nbbs,
            nlocals, outdegree, type, opcodes_sha256, opcodes_crc32, cleaned_opcodes_sha256, cleaned_opcodes_crc32,
            opcodes
    ):
        func = SampleFunction()
        func.offset = offset
        func.size = size
        func.real_size = real_size
        func.name = name
        func.calltype = calltype
        func.cc = cc
        func.cost = cost
        func.ebbs = ebbs
        func.edges = edges
        func.indegree = indegree
        func.nargs = nargs
        func.nbbs = nbbs
        func.nlocals = nlocals
        func.outdegree = outdegree
        func.type = type
        func.opcodes_sha256 = opcodes_sha256
        func.opcodes_crc32 = opcodes_crc32
        func.cleaned_opcodes_sha256 = cleaned_opcodes_sha256
        func.cleaned_opcodes_crc32 = cleaned_opcodes_crc32
        func.opcodes = opcodes
        return func

    def from_json(self, d):
        """
        :param d:
        :return: Sample
        """
        sample = Sample()

        if 'hash_sha256' in d.keys(): sample.hash_sha256 = d['hash_sha256']
        if 'hash_md5' in d.keys(): sample.hash_md5 = d['hash_md5']
        if 'hash_sha1' in d.keys(): sample.hash_sha1 = d['hash_sha1']
        if 'size' in d.keys(): sample.size = int(d['size'])
        if 'code_histogram' in d.keys(): sample.code_histogram = d['code_histogram']
        if 'magic' in d.keys(): sample.magic = d['magic']
        if 'peyd' in d.keys(): sample.peyd = d['peyd']

        if 'ssdeep' in d.keys(): sample.ssdeep = d['ssdeep']
        if 'imphash' in d.keys(): sample.imphash = d['imphash']
        if 'entropy' in d.keys(): sample.entropy = float(d['entropy'])

        if 'file_size' in d.keys(): sample.file_size = int(d['file_size'])
        if 'entry_point' in d.keys(): sample.entry_point = int(d['entry_point'])
        if 'first_kb' in d.keys(): sample.first_kb = d['first_kb']

        if 'overlay_sha256' in d.keys(): sample.overlay_sha256 = d['overlay_sha256']
        if 'overlay_size' in d.keys(): sample.overlay_size = int(d['overlay_size'])
        if 'overlay_ssdeep' in d.keys(): sample.overlay_ssdeep = d['overlay_ssdeep']
        if 'overlay_entropy' in d.keys(): sample.overlay_entropy = float(d['overlay_entropy'])

        if 'build_timestamp' in d.keys(): sample.build_timestamp = date_parser.parse(d['build_timestamp'])

        if 'debug_directories' in d.keys():
            sample.debug_directories = [
                self.create_debug_directory(
                    date_parser.parse(debug_directory['timestamp']) if debug_directory['timestamp'] else None,
                    debug_directory['path'],
                    int(debug_directory['age']) if debug_directory['age'] else None,
                    debug_directory['signature'],
                    debug_directory['guid']
                )
                for debug_directory in d['debug_directories']
            ]

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
                    resource['ssdeep'], resource['entropy'],
                    resource['type_id'] if 'type_id' in resource else None,
                    resource['type_str'] if 'type_str' in resource else None,
                    resource['name_id'] if 'name_id' in resource else None,
                    resource['name_str'] if 'name_str' in resource else None,
                    resource['language_id'] if 'language_id' in resource else None,
                    resource['language_str'] if 'language_str' in resource else None
                )
                for resource in d['resources']
            ]

        if 'functions' in d.keys():
            sample.functions = [
                self.create_function(
                    func['offset'],
                    func['size'],
                    func['real_size'],
                    func['name'],
                    func['calltype'],
                    func['cc'],
                    func['cost'],
                    func['ebbs'],
                    func['edges'],
                    func['indegree'],
                    func['nargs'],
                    func['nbbs'],
                    func['nlocals'],
                    func['outdegree'],
                    func['type'],
                    func['opcodes_sha256'],
                    func['opcodes_crc32'],
                    func['cleaned_opcodes_sha256'],
                    func['cleaned_opcodes_crc32'],
                    func['opcodes']
                )
                for func in d['functions']
            ]

        return sample


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
        if sample.magic is not None: d['magic'] = sample.magic
        if sample.peyd is not None: d['peyd'] = sample.peyd

        if sample.ssdeep is not None: d['ssdeep'] = sample.ssdeep
        if sample.imphash is not None: d['imphash'] = sample.imphash
        if sample.entropy is not None: d['entropy'] = self._format_float(sample.entropy)

        if sample.file_size is not None: d['file_size'] = self._format_int(sample.file_size)
        if sample.entry_point is not None: d['entry_point'] = self._format_int(sample.entry_point)
        if sample.first_kb is not None: d['first_kb'] = sample.first_kb

        if sample.overlay_sha256 is not None: d['overlay_sha256'] = sample.overlay_sha256
        if sample.overlay_size is not None: d['overlay_size'] = self._format_int(sample.overlay_size)
        if sample.overlay_ssdeep is not None: d['overlay_ssdeep'] = sample.overlay_ssdeep
        if sample.overlay_entropy is not None: d['overlay_entropy'] = self._format_float(sample.overlay_entropy)

        if sample.build_timestamp is not None: d['build_timestamp'] = self._format_timestamp(sample.build_timestamp)

        if sample.debug_directories:
            d['debug_directories'] = [
                {
                    'timestamp': debug_directory.timestamp,
                    'path': debug_directory.path,
                    'age': debug_directory.age,
                    'signature': debug_directory.signature,
                    'guid': debug_directory.guid
                } for debug_directory in sample.debug_directories
            ]

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

        if sample.functions:
            d['functions'] = []
            for func in sample.functions:
                json_func = {
                    'offset': func.offset,
                    'size': func.size,
                    'real_size': func.real_size,
                    'name': func.name,
                    'calltype': func.calltype,
                    'cc': func.cc,
                    'cost': func.cost,
                    'ebbs': func.ebbs,
                    'edges': func.edges,
                    'indegree': func.indegree,
                    'nargs': func.nargs,
                    'nbbs': func.nbbs,
                    'nlocals': func.nlocals,
                    'outdegree': func.outdegree,
                    'type': func.type,
                    'opcodes_sha256': func.opcodes_sha256,
                    'opcodes_crc32': func.opcodes_crc32,
                    'cleaned_opcodes_sha256': func.cleaned_opcodes_sha256,
                    'cleaned_opcodes_crc32': func.cleaned_opcodes_crc32,
                    'opcodes': func.opcodes,
                }

                d['functions'].append(json_func)

        if self.filter:
            d = {k: v for k, v in d.items() if self.filter in k}
        return d
