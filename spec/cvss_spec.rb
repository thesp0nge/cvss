require 'spec_helper'

describe "CVSS library" do
  let(:cvss) { Cvss::Engine.new() } 
  it "should have a parser method" do
    cvss.should respond_to(:parse)
    
  end
  it "should recognize a bad input" do
    cvss.parse("this is a test string").should be_false
  end

  it "should recognize a good input" do
    cvss.parse("AV:N/AC:L/Au:N/C:N/I:N/A:C").should be_true
  end
end
