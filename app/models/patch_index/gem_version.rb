require 'ripper'

module PatchIndex
  module GemVersion
    def self.path(gemspec)
      paths = gemspec.lines.filter_map do |line|
        case line.strip
        when %r{\Arequire_relative\s+['"]((?:\./)?lib/[\w/-]+/version)(?:\.rb)?['"]\z},
             %r{\Arequire\s+['"]\./(lib/[\w/-]+/version)(?:\.rb)?['"]\z},
             %r{\Arequire File\.expand_path\(['"]\.\./(lib/[\w/-]+/version)['"], __FILE__\)\z}
          "#{$1.delete_prefix('./')}.rb"
        when %r{\Arequire\s+['"]([\w-]+(?:/[\w-]+)*/version)(?:\.rb)?['"]\z}
          "lib/#{$1}.rb"
        end
      end.uniq
      paths.first if paths.one?
    end

    def self.read(gemspec, source)
      assignments = gemspec.scan(/^\s*\w+\.version\s*=\s*((?:[A-Z]\w*::)+[A-Z]\w*)(?:\.(?:dup|freeze|to_s))?\s*$/)
      return unless assignments.one?
      constant = assignments.first.first
      tree = Ripper.sexp(source)
      return unless tree
      values = literals(tree[1], constant.split('::'))
      { 'assignment' => constant, 'value' => values.first } if values.one? && values.first
    end

    def self.literals(statements, names)
      statements.flat_map do |node|
        node = [:module, node[1], node[3]] if node.first == :class
        case node
        in [:module, [:const_ref, [:@const, name, _]], [:bodystmt, children, nil, nil, nil]]
          name == names.first ? literals(children, names.drop(1)) : []
        in [:assign, [:var_field, [:@const, name, _]], value] if names == [name]
          value = value[1] if value in [:call, _, _, [:@ident, 'freeze', _]]
          if value in [:string_literal, [:string_content, [:@tstring_content, literal, _]]]
            [(literal if literal.match?(/\A[\w.+-]+\z/))]
          else
            [nil]
          end
        else
          []
        end
      end
    end
  end
end
