from insights.specs import Specs
from insights.parsr.query import from_dict
from . import queryview


class LSOFParser(object):

    def _calc_indexes(self, line):
        self.header_row = line
        self.name_idx = self.header_row.index(" NAME")
        self.pid_idx = self.header_row.index("  PID")
        _, self.mid_cols = self.header_row[:self.name_idx].split(None, 1)
        self.mid_cols = "  " + self.mid_cols
        self.indexes = {}
        self.col_names = self.mid_cols.split()
        for col_name in self.col_names:
            self.indexes[col_name] = self.mid_cols.index(col_name) + len(col_name)
        self.indexes["FD"] += 2

    def _split_middle(self, middle):
        mid_dict = {}
        offset = 0
        for col in self.col_names:
            idx = self.indexes[col]
            key = col.strip().replace("/", "_").lower()
            mid_dict[key] = middle[offset:idx].strip()
            offset = idx
        return mid_dict

    def _start(self, content):
        """
        Consumes lines from content until the HEADER is found and processed.
        Returns an iterator over the remaining lines.
        """
        content = iter(content)

        line = next(content)
        while 'COMMAND ' not in line:
            line = next(content)

        self._calc_indexes(line)
        return content

    def _parse_line(self, line):
        """
        Given a line, returns a dictionary for that line. Requires _start to be
        called first.
        """
        command, rest = line[:self.pid_idx], line[self.pid_idx:]
        name = line[self.name_idx:]
        middle_dict = self._split_middle(rest[:self.name_idx - len(command)])
        middle_dict["command"] = command.strip()
        middle_dict["name"] = name.strip()
        return middle_dict

    def parse(self, content):
        """
        Parse the content for the entire input file.
        """
        for line in self._start(content):
            yield self._parse_line(line)


@queryview(Specs.lsof)
def lsof(ctx):
    results = []
    for r in LSOFParser().parse(ctx.content):
        results.append(r)

    return from_dict({"entries": results})
