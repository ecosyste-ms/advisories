FactoryBot.define do
  factory :related_package do
    association :advisory
    association :package
  end
end
