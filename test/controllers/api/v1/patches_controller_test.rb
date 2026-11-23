require 'test_helper'

class Api::V1::PatchesControllerTest < ActionDispatch::IntegrationTest
  setup do
    @patch = create(:patch, headers: { 'Forwarded' => 'not-needed' })
    @release = create(:patch_release, distribution: 'debian', package_name: 'rust-h2', version: '0.4.4-1', upstream_version: '0.4.4',
      repository_url: 'https://github.com/hyperium/h2')
    @fix = create(:patch_occurrence, patch: @patch, patch_release: @release, name: 'CVE-2024-27308.patch', position: 2,
      advisory_ids: ['CVE-2024-27308'], declaration: { 'advisory_evidence' => { 'CVE-2024-27308' => ['name'] } })
    create(:patch_occurrence, patch: @patch, patch_release: create(:patch_release, distribution: 'ubuntu'))
    create(:patch_occurrence)
    @advisory = create(:advisory, uuid: 'GHSA-8r5v-vm4m-4g25', identifiers: %w[GHSA-8r5v-vm4m-4g25 CVE-2024-27308])
  end

  test 'a filtered list returns each patch once with only the matching declarations' do
    get api_v1_patches_path(repository_url: 'https://github.com/hyperium/h2', advisory: 'GHSA-8r5v-vm4m-4g25')
    assert_response :success
    patch = response.parsed_body.sole
    assert_equal [@patch.sha256, @patch.byte_size, { 'Forwarded' => 'not-needed' }], patch.values_at('sha256', 'byte_size', 'headers')
    assert_equal [api_v1_patch_url(@patch), patch_url(@patch), download_patch_url(@patch)], patch.values_at('api_url', 'html_url', 'download_url')
    occurrence = patch.fetch('occurrences').sole
    assert_equal ['CVE-2024-27308.patch', 2, { 'CVE-2024-27308' => 'patch_name' }], occurrence.values_at('name', 'position', 'advisory_roles')
    assert_equal ['debian', 'rust-h2', '0.4.4-1', '0.4.4', 'https://github.com/hyperium/h2'],
      occurrence.fetch('release').values_at('distribution', 'package_name', 'version', 'upstream_version', 'repository_url')
    assert_equal ecosystem_package_url('debian', 'rust-h2', tab: 'patches'), occurrence.dig('release', 'package_url')
    advisory = patch.fetch('referenced_advisories').sole
    assert_equal ['GHSA-8r5v-vm4m-4g25', ['CVE-2024-27308']], advisory.values_at('uuid', 'matched_identifiers')
  end

  test 'the list paginates patches and rejects an invalid PURL' do
    get api_v1_patches_path(per_page: 1)
    assert_equal 1, response.parsed_body.size
    assert_equal '2', response.headers['total-count']
    get api_v1_patches_path(purl: 'not a purl')
    assert_response :bad_request
    assert response.parsed_body['error'].present?
  end

  test 'a patch is fetched by digest with every declaration' do
    get api_v1_patch_path(@patch)
    assert_response :success
    assert_equal %w[debian ubuntu], response.parsed_body.fetch('occurrences').map { |o| o.dig('release', 'distribution') }
    get api_v1_patch_path(create(:patch))
    assert_response :not_found
  end
end
