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

  it "should recognize Access Vector" do
    cvss.parse("AV:N/AC:L/Au:N/C:N/I:N/A:C")
    cvss.base[:av].should == "N"
  end

  it "should recognize Access Complexity" do
    cvss.parse("AV:N/AC:L/Au:N/C:N/I:N/A:C")
    cvss.base[:ac].should == "L"
  end
  it "should recognize Authentication" do
    cvss.parse("AV:N/AC:L/Au:N/C:N/I:N/A:C")
    cvss.base[:au].should == "N"
  end
  it "should recognize Confidentiality" do
    cvss.parse("AV:N/AC:L/Au:N/C:N/I:N/A:C")
    cvss.base[:c].should == "N"
  end
  it "should recognize Integrity" do
    cvss.parse("AV:N/AC:L/Au:N/C:N/I:N/A:C")
    cvss.base[:i].should == "N"
  end
  it "should recognize Availability" do
    cvss.parse("AV:N/AC:L/Au:N/C:N/I:N/A:C")
    cvss.base[:a].should == "C"
  end
end
