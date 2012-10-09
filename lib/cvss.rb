require "cvss/version"
require 'cvss/parser'
require 'cvss/helpers'

module Cvss 
  class Engine
    include Cvss::Parser
    include Cvss::Helpers

  end
end
