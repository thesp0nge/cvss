module Cvss
  module Parser

    attr_reader :vector

    # It parses a string and it says if it's a good CVSS vector or not.
    def parse(string)
      toks = string.split("/")
      parse_base(toks)
    end


    private
    # AV:N/AC:L/Au:N/C:N/I:N/A:C
    def parse_base(tokens)
      return false if tokens.count != 6
      av = tokens[0].split(":")
      return false if av.count != 2 or av[0] != "AV" or (av[1] != "N" and av[1] != "L" and av[1] != "A")
      
      

    end
  end
end
