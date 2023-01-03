class Advisory < ApplicationRecord
  belongs_to :source

  counter_culture :source

  scope :ecosystem, ->(ecosystem) { where("? <@ ANY ( ARRAY(select jsonb_array_elements ( packages )) )",{ecosystem:ecosystem}.to_json) }
  scope :package_name, ->(package_name) { where("? <@ ANY ( ARRAY(select jsonb_array_elements ( packages )) )",{package_name:package_name}.to_json) }
  scope :severity, ->(severity) { where(severity: severity) }

  def to_s
    uuid
  end

  def to_param
    uuid
  end

  def self.packages
    all.select(:packages).map{|a| a.packages.map{|p| p.except("versions") } }.flatten.uniq
  end

  def self.ecosystems
    all.select(:packages).map{|a| a.packages.map{|p| p['ecosystem'] } }.flatten.uniq
  end

  def ecosystems
    packages.map{|p| p['ecosystem'] }.uniq
  end

  def package_names
    packages.map{|p| p['package_name'] }.uniq
  end
end
