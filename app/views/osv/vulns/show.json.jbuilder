transformer = Osv::VulnerabilityTransformer.new(@advisory)
osv = transformer.transform

json.merge! osv
