FactoryBot.define do
  factory :source do
    sequence(:name) { |n| "Source #{n}" }
    kind { "github" }
    url { "https://github.com/test/test" }
  end
end