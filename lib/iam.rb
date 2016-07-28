require_relative '../../resource/lib/resource.rb'

class IAM < Resource
  require_relative 'iam/role'
  require_relative 'iam/policy'

  def initialize(*args)
    super(*args)
    @aws_client = Aws::IAM::Client.new(region: @desired_properties[:region])
  end
end
