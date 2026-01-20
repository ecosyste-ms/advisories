require "test_helper"

class Osv::QueryServiceTest < ActiveSupport::TestCase
  setup do
    @source = create(:source)
    @npm_advisory = create(:advisory,
      source: @source,
      uuid: "GHSA-npm-0001",
      packages: [
        { "ecosystem" => "npm", "package_name" => "lodash", "versions" => [] }
      ]
    )
    @pypi_advisory = create(:advisory,
      source: @source,
      uuid: "GHSA-pypi-0001",
      packages: [
        { "ecosystem" => "pypi", "package_name" => "django", "versions" => [] }
      ]
    )
    @ruby_advisory = create(:advisory,
      source: @source,
      uuid: "GHSA-ruby-0001",
      identifiers: ["GHSA-ruby-0001", "CVE-2023-99999"],
      packages: [
        { "ecosystem" => "rubygems", "package_name" => "rails", "versions" => [] }
      ]
    )
  end

  test "finds advisory by ecosystem and name" do
    service = Osv::QueryService.new(package: { ecosystem: "npm", name: "lodash" })
    result = service.find_vulnerabilities

    assert_equal 1, result[:advisories].length
    assert_equal "GHSA-npm-0001", result[:advisories].first.uuid
  end

  test "finds advisory by OSV ecosystem name (PyPI)" do
    service = Osv::QueryService.new(package: { ecosystem: "PyPI", name: "django" })
    result = service.find_vulnerabilities

    assert_equal 1, result[:advisories].length
    assert_equal "GHSA-pypi-0001", result[:advisories].first.uuid
  end

  test "finds advisory by OSV ecosystem name (RubyGems)" do
    service = Osv::QueryService.new(package: { ecosystem: "RubyGems", name: "rails" })
    result = service.find_vulnerabilities

    assert_equal 1, result[:advisories].length
    assert_equal "GHSA-ruby-0001", result[:advisories].first.uuid
  end

  test "normalizes ecosystem names case-insensitively" do
    service = Osv::QueryService.new(package: { ecosystem: "NPM", name: "lodash" })
    result = service.find_vulnerabilities

    assert_equal 1, result[:advisories].length
  end

  test "finds advisory by PURL" do
    service = Osv::QueryService.new(purl: "pkg:npm/lodash@4.17.21")
    result = service.find_vulnerabilities

    assert_equal 1, result[:advisories].length
    assert_equal "GHSA-npm-0001", result[:advisories].first.uuid
  end

  test "finds advisory by PURL without version" do
    service = Osv::QueryService.new(purl: "pkg:npm/lodash")
    result = service.find_vulnerabilities

    assert_equal 1, result[:advisories].length
  end

  test "finds advisory by gem PURL" do
    service = Osv::QueryService.new(purl: "pkg:gem/rails")
    result = service.find_vulnerabilities

    assert_equal 1, result[:advisories].length
    assert_equal "GHSA-ruby-0001", result[:advisories].first.uuid
  end

  test "raises error when version in both purl and package" do
    service = Osv::QueryService.new(purl: "pkg:npm/lodash@4.17.21", package: { version: "4.17.20" })

    assert_raises ArgumentError do
      service.find_vulnerabilities
    end
  end

  test "returns empty results for unknown package" do
    service = Osv::QueryService.new(package: { ecosystem: "npm", name: "nonexistent" })
    result = service.find_vulnerabilities

    assert_equal 0, result[:advisories].length
    assert_nil result[:next_page_token]
  end

  test "returns empty results for invalid PURL" do
    service = Osv::QueryService.new(purl: "invalid-purl")
    result = service.find_vulnerabilities

    assert_equal 0, result[:advisories].length
  end

  test "paginates results" do
    # Create more advisories to test pagination
    102.times do |i|
      create(:advisory,
        source: @source,
        uuid: "GHSA-page-#{i.to_s.rjust(4, '0')}",
        packages: [{ "ecosystem" => "npm", "package_name" => "test-pagination", "versions" => [] }]
      )
    end

    service = Osv::QueryService.new(package: { ecosystem: "npm", name: "test-pagination" })
    result = service.find_vulnerabilities

    assert_equal 100, result[:advisories].length
    assert_not_nil result[:next_page_token]

    # Request second page
    service2 = Osv::QueryService.new(
      package: { ecosystem: "npm", name: "test-pagination" },
      page_token: result[:next_page_token]
    )
    result2 = service2.find_vulnerabilities

    assert_equal 2, result2[:advisories].length
    assert_nil result2[:next_page_token]
  end

  test "encodes page token correctly" do
    service = Osv::QueryService.new({})
    token = service.encode_page_token(100)

    assert_not_nil token
    assert_equal 100, service.decode_page_token(token)
  end

  test "decodes invalid page token as 0" do
    service = Osv::QueryService.new({})
    assert_equal 0, service.decode_page_token("invalid!!!")
  end

  test "decodes nil page token as 0" do
    service = Osv::QueryService.new({})
    assert_equal 0, service.decode_page_token(nil)
  end

  test "find_by_id finds by uuid" do
    advisory = Osv::QueryService.find_by_id("GHSA-npm-0001")

    assert_not_nil advisory
    assert_equal "GHSA-npm-0001", advisory.uuid
  end

  test "find_by_id finds by CVE identifier" do
    advisory = Osv::QueryService.find_by_id("CVE-2023-99999")

    assert_not_nil advisory
    assert_equal "GHSA-ruby-0001", advisory.uuid
  end

  test "find_by_id returns nil for unknown id" do
    advisory = Osv::QueryService.find_by_id("GHSA-nonexistent")

    assert_nil advisory
  end

  test "returns all advisories when no filters provided" do
    service = Osv::QueryService.new({})
    result = service.find_vulnerabilities

    assert_equal 3, result[:advisories].length
  end

  test "orders results by updated_at desc" do
    @npm_advisory.update_column(:updated_at, 1.day.ago)
    @pypi_advisory.update_column(:updated_at, 2.days.ago)
    @ruby_advisory.update_column(:updated_at, 1.hour.ago)

    service = Osv::QueryService.new({})
    result = service.find_vulnerabilities

    assert_equal "GHSA-ruby-0001", result[:advisories].first.uuid
    assert_equal "GHSA-pypi-0001", result[:advisories].last.uuid
  end
end
