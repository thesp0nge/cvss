# -*- encoding: utf-8 -*-
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'cvss/version'

Gem::Specification.new do |gem|
  gem.name          = "cvss"
  gem.version       = Cvss::VERSION
  gem.authors       = ["Paolo Perego"]
  gem.email         = ["thesp0nge@gmail.com"]
  gem.description   = %q{cvss is a rubygem for parsing cvss vector and calculate cvss score given some parameter.}
  gem.summary       = %q{cvss is a rubygem for parsing cvss vector and calculate cvss score given some parameter.}
  gem.homepage      = ""

  gem.files         = `git ls-files`.split($/)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ["lib"]

  gem.add_development_dependency "rake"
  gem.add_development_dependency "rspec"

end
