FactoryBot.define do
  factory :package do
    sequence(:name) { |n| "package#{n}" }
    ecosystem { "npm" }
    version_numbers { {} }
    advisories_count { 0 }
    critical { false }
  end
end