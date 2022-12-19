class Advisory < ApplicationRecord
  belongs_to :source

  counter_culture :source
end
