# encoding: utf-8
require 'spec_helper'
require "logstash/filters/decode_wazuh_events"

describe LogStash::Filters::DecodeWazuhEvents do
  describe "Set to Hello World" do
    let(:config) do <<-CONFIG
      filter {
        decode_wazuh_events {
          field => "message"
        }
      }
    CONFIG
    end

    sample("message" => "some text") do
      expect(subject.get("message")).to eq('some text')
    end
  end
end
