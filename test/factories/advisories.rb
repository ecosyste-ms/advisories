FactoryBot.define do
  factory :advisory do
    association :source
    sequence(:uuid) { |n| "CVE-2023-#{n.to_s.rjust(4, '0')}" }
    title { "Test Advisory" }
    description { "Test description" }
    published_at { Time.current }
    cvss_score { 7.5 }
    severity { "high" }
    packages { 
      [
        {
          "ecosystem" => "npm",
          "package_name" => "test-package",
          "versions" => [
            {
              "vulnerable_version_range" => "< 1.0.0"
            }
          ]
        }
      ]
    }
    references { ["https://example.com"] }
    withdrawn_at { nil }
  end
end