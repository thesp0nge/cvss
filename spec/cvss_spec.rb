require 'spec_helper'

describe "CVSS library" do
  let(:cvss) { Cvss::Engine.new() } 
  describe "parser" do

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
  
  describe "helper" do
    it "should have a data integrity helper" do
      cvss.should respond_to(:data_integrity)
    end
    it "should have a data confidentiality helper" do
      cvss.should respond_to(:data_confidentiality)
    end
    it "should have a data availability helper" do
      cvss.should respond_to(:data_availability)
    end

    it "should recognize Confidentiality" do
      cvss.parse("AV:N/AC:L/Au:N/C:N/I:N/A:C")
      cvss.data_confidentiality.should == "N"
    end
    it "should recognize Integrity" do
      cvss.parse("AV:N/AC:L/Au:N/C:N/I:N/A:C")
      cvss.data_integrity.should == "N"
    end
    it "should recognize Availability" do
      cvss.parse("AV:N/AC:L/Au:N/C:N/I:N/A:C")
      cvss.data_availability.should == "C"
    end
  end

  it "has a score method"  do
    cvss.should   respond_to(:score)
  end

  it "should calculate the CVSS score" do
    cvss.score("AV:N/AC:L/Au:N/C:P/I:P/A:P").should  == 7.5
  end
end
