module Net
  module DNS
    class RR
      #
      # = Name Authority Pointer (NAPTR)
      # NAPTR records are most commonly used for applications in Internet telephony,
      # for example, in the mapping of servers and user addresses in the Session Initiation Protocol (SIP).
      # The combination of NAPTR records with Service Records (SRV) allows
      # the chaining of multiple records to form complex rewrite rules which produce new domain labels or
      # uniform resource identifiers (URIs).
      # The DNS type code for the NAPTR record is 35
      #
      class NAPTR < RR
        attr_reader :order, :preference, :flags, :service, :regexp, :replacement

        def value
          "#{@order} #{@preference} \"#{@flags}\" \"#{@service}\" \"#{@regexp}\" #{@replacement.to_s}"
        end

        def set_type
          @type = Net::DNS::RR::Types.new("NAPTR")
        end

        def subclass_new_from_binary(data, offset)
          @order               = data.unpack("@#{offset} n")[0]
          offset               += 2
          @preference          = data.unpack("@#{offset} n")[0]
          offset               += 2
          @flags, offset       = self.get_string(data, offset)
          @service, offset     = self.get_string(data, offset)
          @regexp, offset      = self.get_string(data, offset)
          @replacement, offset = self.get_string(data, offset)
          offset
        end

        def subclass_new_from_string(input)
          if input.length > 0
            values       = input.split(" ")
            @order       = values[0].to_i
            @preference  = values[1].to_i
            @flags       = values[2].gsub!("\"", "")
            @service     = values[3].gsub!("\"", "")
            @regexp      = values[4]
            @replacement = values[5]
          end
        end

        def get_string(data, offset)
          len    = data.unpack("@#{offset} C")[0]
          offset += 1
          str    = data[offset..offset+len-1]
          offset += len
          [str, offset]
        end

      end
    end
  end
end
