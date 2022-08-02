# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require 'json'


class LogStash::Filters::DecodeJsonWinevents < LogStash::Filters::Base
  config_name "decode_json_winevents"

  # Set the field to decode
  config :field, :validate => :string, :default => "message",  :required => false

  AUDITFAILURE = 0x10000000000000
  AUDITSUCCESS = 0x20000000000000

  public
  def register
  end # def register

  public
  def filter(event)
    # Grab the field from the Logstash event
    @logger.debug? && @logger.info("field in configuration is defined as: #{@field}")
    event = event.get("[#{@field}]")
    @logger.debug? && @logger.info("value found in field is: #{event}")

    # Make an exception for the EventData by renaming the snake_case to CamelCase
    # doc_hash[:winlog][:event_data] = doc_hash[:winlog][:event_data].to_camel_keys

    # Generate required fields
    doc_hash[:event] = {:original => xml, :code => doc_hash[:winlog][:event_id], :provider => doc_hash[:winlog][:provider_name], :kind => "event"}
    if doc_hash[:winlog][:keywords].hex & AUDITFAILURE > 0
      doc_hash[:event][:outcome] = "failure"
    elsif doc_hash[:winlog][:keywords].hex & AUDITSUCCESS > 0
      doc_hash[:event][:outcome] = "success"
    end
    doc_hash[:event][:dataset] = "windows.security"
    doc_hash[:log] = {:level => doc_hash[:winlog][:rendering_info][:level].downcase}
    doc_hash[:@timestamp] = LogStash::Timestamp.parse_iso8601(doc_hash[:winlog][:time_created_system_time])
    doc_hash[:winlog][:process] = {:pid => doc_hash[:winlog][:execution_process_id], :thread => {:id => doc_hash[:winlog][:execution_thread_id]}}
    doc_hash[:winlog].merge({:message => doc_hash[:winlog][:rendering_info][:message]})
    doc_hash[:winlog][:channel] = doc_hash[:winlog][:rendering_info][:channel]
    doc_hash[:agent] = {:type => "winlogbeat"}

    # Delete fields that are no longer needed
    doc_hash[:winlog].delete(:execution_process_id)
    doc_hash[:winlog].delete(:execution_thread_id)
    doc_hash[:winlog].delete(:rendering_info)
    doc_hash[:winlog].delete(:time_created_system_time)
    doc_hash[:winlog].delete(:level)
    doc_hash[:winlog].delete(:security)
    event.remove("message")

    # Clean up our own inconsistent field names
    doc_hash[:winlog][:record_id] = doc_hash[:winlog].delete(:event_record_id)
    doc_hash[:winlog][:computer_name] = doc_hash[:winlog].delete(:computer)

    # Populate event with data from the Ruby hash
    doc_hash.keys.each do |key|
      event.set("[#{key}]", doc_hash[:"#{key}"])
    end

    filter_matched(event)
  end # def filter
end # class LogStash::Filters::DecodeWazuhEvents
