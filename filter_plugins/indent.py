class FilterModule(object):

    def indent_block(self, value, indent=2):
        return "\n".join([' '*indent + l for l in value.splitlines()])

    def filters(self):
        return {
            'indent_block': self.indent_block,
        }
