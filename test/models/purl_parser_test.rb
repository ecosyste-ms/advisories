require "test_helper"

class PurlParserTest < ActiveSupport::TestCase
  context ".parse" do
    should "parse npm PURL correctly" do
      purl = "pkg:npm/lodash@4.17.20"
      result = PurlParser.parse(purl)
      
      assert_equal "npm", result[:ecosystem]
      assert_equal "lodash", result[:package_name]
      assert_nil result[:namespace]
      assert_equal "4.17.20", result[:version]
      assert_equal purl, result[:original_purl]
    end

    should "parse npm scoped package PURL correctly" do
      purl = "pkg:npm/%40angular/core@12.0.0"
      result = PurlParser.parse(purl)
      
      assert_equal "npm", result[:ecosystem]
      assert_equal "core", result[:package_name]
      assert_equal "@angular", result[:namespace]
      assert_equal "12.0.0", result[:version]
      assert_equal purl, result[:original_purl]
    end

    should "parse pypi PURL correctly" do
      purl = "pkg:pypi/django@3.2.0"
      result = PurlParser.parse(purl)
      
      assert_equal "pypi", result[:ecosystem]
      assert_equal "django", result[:package_name]
      assert_equal "3.2.0", result[:version]
    end

    should "parse gem PURL correctly and map to rubygems ecosystem" do
      purl = "pkg:gem/rails@7.0.0"
      result = PurlParser.parse(purl)
      
      assert_equal "rubygems", result[:ecosystem]
      assert_equal "rails", result[:package_name]
      assert_equal "7.0.0", result[:version]
    end

    should "parse golang PURL correctly and map to go ecosystem" do
      purl = "pkg:golang/github.com/gin-gonic/gin@v1.7.0"
      result = PurlParser.parse(purl)
      
      assert_equal "go", result[:ecosystem]
      assert_equal "gin", result[:package_name]
      assert_equal "v1.7.0", result[:version]
    end

    should "parse maven PURL correctly" do
      purl = "pkg:maven/org.springframework/spring-core@5.3.0"
      result = PurlParser.parse(purl)
      
      assert_equal "maven", result[:ecosystem]
      assert_equal "spring-core", result[:package_name]
      assert_equal "org.springframework", result[:namespace]
      assert_equal "5.3.0", result[:version]
    end

    should "return nil for unsupported ecosystem" do
      purl = "pkg:unsupported/package@1.0.0"
      result = PurlParser.parse(purl)
      
      assert_nil result
    end

    should "return nil for blank PURL" do
      assert_nil PurlParser.parse("")
      assert_nil PurlParser.parse(nil)
      assert_nil PurlParser.parse("   ")
    end

    should "return nil for invalid PURL format" do
      result = PurlParser.parse("invalid-purl")
      assert_nil result
    end

    should "handle PURL without version" do
      purl = "pkg:npm/lodash"
      result = PurlParser.parse(purl)
      
      assert_equal "npm", result[:ecosystem]
      assert_equal "lodash", result[:package_name]
      assert_nil result[:version]
    end
  end

  context ".map_ecosystem" do
    should "map PURL types to correct ecosystems" do
      assert_equal "npm", PurlParser.map_ecosystem("npm")
      assert_equal "pypi", PurlParser.map_ecosystem("pypi") 
      assert_equal "rubygems", PurlParser.map_ecosystem("gem")
      assert_equal "maven", PurlParser.map_ecosystem("maven")
      assert_equal "nuget", PurlParser.map_ecosystem("nuget")
      assert_equal "go", PurlParser.map_ecosystem("golang")
      assert_equal "go", PurlParser.map_ecosystem("go")
      assert_equal "cargo", PurlParser.map_ecosystem("cargo")
    end

    should "handle case insensitive mapping" do
      assert_equal "npm", PurlParser.map_ecosystem("NPM")
      assert_equal "rubygems", PurlParser.map_ecosystem("GEM")
    end

    should "return nil for unsupported ecosystem" do
      assert_nil PurlParser.map_ecosystem("unsupported")
      assert_nil PurlParser.map_ecosystem(nil)
    end
  end

  context ".generate_purl" do
    should "generate PURL for npm package" do
      purl = PurlParser.generate_purl(ecosystem: "npm", package_name: "lodash")
      assert_equal "pkg:npm/lodash", purl
    end

    should "generate PURL with version for npm package" do
      purl = PurlParser.generate_purl(ecosystem: "npm", package_name: "lodash", version: "4.17.20")
      assert_equal "pkg:npm/lodash@4.17.20", purl
    end

    should "generate PURL for rubygems package" do
      purl = PurlParser.generate_purl(ecosystem: "rubygems", package_name: "rails")
      assert_equal "pkg:gem/rails", purl
    end

    should "generate PURL for pypi package" do
      purl = PurlParser.generate_purl(ecosystem: "pypi", package_name: "django")
      assert_equal "pkg:pypi/django", purl
    end

    should "generate PURL with namespace for maven package" do
      purl = PurlParser.generate_purl(
        ecosystem: "maven", 
        package_name: "spring-core", 
        namespace: "org.springframework"
      )
      assert_equal "pkg:maven/org.springframework/spring-core", purl
    end

    should "return nil for unsupported ecosystem" do
      purl = PurlParser.generate_purl(ecosystem: "unsupported", package_name: "package")
      assert_nil purl
    end

    should "handle nil ecosystem" do
      purl = PurlParser.generate_purl(ecosystem: nil, package_name: "package")
      assert_nil purl
    end
  end

  context ".reverse_map_ecosystem" do
    should "reverse map ecosystems to PURL types" do
      assert_equal "npm", PurlParser.reverse_map_ecosystem("npm")
      assert_equal "pypi", PurlParser.reverse_map_ecosystem("pypi")
      assert_equal "gem", PurlParser.reverse_map_ecosystem("rubygems")
      assert_equal "maven", PurlParser.reverse_map_ecosystem("maven")
      # Note: Both 'golang' and 'go' map to 'go' ecosystem, but reverse mapping returns the first match
      assert_equal "go", PurlParser.reverse_map_ecosystem("go")
    end

    should "return nil for unsupported ecosystem" do
      assert_nil PurlParser.reverse_map_ecosystem("unsupported")
      assert_nil PurlParser.reverse_map_ecosystem(nil)
    end
  end
end