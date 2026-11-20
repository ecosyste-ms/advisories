require 'test_helper'

class PatchIndex::GemVersionTest < ActiveSupport::TestCase
  test 'version evidence comes from the required file and matching namespace' do
    spec = "require 'widget/version'\ns.version = Widget::Core::VERSION\n"
    assert_equal 'lib/widget/version.rb', PatchIndex::GemVersion.path(spec)
    source = "module Other\n VERSION = '9.9'\nend\nmodule Widget\n module Core\n VERSION = '1.2'.freeze\n end\nend"
    result = PatchIndex::Component.resolve('manifest' => 'widget.gemspec', 'body' => spec + "s.name = 'widget'\n", 'url' => 'archive',
      'version_file' => { 'url' => 'archive#lib/widget/version.rb', 'body' => source })
    assert_equal '1.2', result.dig('identity', 'version')
    assert_nil PatchIndex::GemVersion.read(spec, source.sub('module Core', 'module Another'))
    assert_nil PatchIndex::GemVersion.read(spec, source.sub("'1.2'.freeze", 'version_from_git'))
    assert_nil PatchIndex::GemVersion.path("require_relative '../elsewhere/version'")
  end
end
