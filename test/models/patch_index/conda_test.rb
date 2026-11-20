require 'test_helper'

class PatchIndex::CondaTest < ActionDispatch::IntegrationTest
  setup do
    @http = PatchIndex::Http.new(cache: ActiveSupport::Cache::NullStore.new, interval: 0)
  end

  def build(name, version, build, number, recipe)
    { 'name' => name, 'version' => version, 'build' => build, 'build_number' => number, 'subdir' => 'linux-64',
      'archive_url' => "https://conda.anaconda.org/conda-forge/linux-64/#{name}-#{version}-#{build}.conda",
      'recipe' => "info/recipe/#{recipe}" }
  end

  def serve(url, filename)
    bytes = file_fixture("patch_index/conda_nix/#{filename}").binread
    stub_request(:get, url).to_return(body: bytes)
    Digest::SHA256.hexdigest(bytes)
  end

  test 'published conda builds retain the rendered series, exact platform build and bytes' do
    importer = PatchIndex::Conda.new(@http)
    pin = build('bzip2', '1.0.8', 'hda65f42_10', 10, 'meta.yaml')
    pin['archive_sha256'] = serve(pin['archive_url'], 'bzip2.conda')
    2.times { importer.import(pin) }
    get api_v1_patches_path, params: { distribution: 'conda-forge' }
    assert_response :success
    assert_equal 3, response.parsed_body.size
    assert_equal %w[0f47e20a9010b4b39b619fa2f6b21865829b62e1fd66d95a2582bcc8b88b9c47 1e508465556fc26ef90fd7ad02415a5d000c7f66e2a85efbfbaa07c2757c220f d589062eecb8c0247e087113d1938a10360d4d69846fb90193178e04c1f69772], response.parsed_body.pluck('sha256').sort
    occurrences = response.parsed_body.flat_map { |r| r.fetch('occurrences') }.sort_by { |o| o.dig('declaration', 'position') }
    assert_equal [1, 2, 3], occurrences.map { |o| o.dig('declaration', 'position') }
    assert_equal 'linux-64/hda65f42_10', occurrences.first.dig('downstream', 'revision')
    assert_nil occurrences.first.fetch('purl')
    assert_nil occurrences.first.dig('assertions', 'verified')
    get patch_path(response.parsed_body.first.fetch('sha256'))
    assert_select '.patch-declaration', text: /linux-64\/hda65f42_10/
    assert_raises(IOError) { importer.import(pin.merge('recipe' => 'info/recipe/missing.yaml')) }
    assert_raises(IOError) { importer.import(pin.merge('build' => 'another')) }
    assert_equal 3, PatchOccurrence.count

    empty = build('ripgrep', '15.2.0', 'hf19af3b_1', 1, 'rendered_recipe.yaml')
    empty['archive_sha256'] = serve(empty['archive_url'], 'ripgrep.conda')
    assert_empty importer.import(empty).patch_occurrences
  end

end
