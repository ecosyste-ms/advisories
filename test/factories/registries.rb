FactoryBot.define do
  factory :registry do
    name { "npmjs.org" }
    url { "https://www.npmjs.com" }
    ecosystem { "npm" }
    default { true }
    packages_count { 1000000 }
    github { false }
    metadata { {} }
    purl_type { "npm" }
  end
end