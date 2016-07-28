class IAM
  class Role < self
    METADATA = {
      role_name: [:key, :create],
      Effect: [:create],
      Principal: [:create],
      Action: [:create],
      policies: [:update_policy]
    }.freeze

    private 

    def raw_properties
      role = @aws_client.get_role(role_name: @desired_properties[:role_name]).role
      policies = @aws_client.list_attached_role_policies(role_name: @desired_properties[:role_name]).attached_policies
      props = role.to_h.merge!(policies: policies)
    rescue Aws::IAM::Errors::NoSuchEntity
      nil
    end

    def parse_properties(raw_props)
      props = raw_props
      arns = []
      raw_props[:policies].each do |policy|
        arns[arns.length] = policy.policy_arn
      end
      props[:policies] = arns 
      Resource::Properties.new(self.class, props)
    end

    def format_diff!(diff)
      if @current_properties[:policies].uniq.sort == @desired_properties[:policies].uniq.sort
        diff.delete(:policies)
      end
      diff
    end

    def build_role_policy_document
      @desired_properties[:assume_role_policy_document] = {
        "Version" => "2012-10-17",
        "Statement" => [
          {
            'Effect' => @desired_properties[:Effect],
            'Principal' => @desired_properties[:Principal],
            'Action' => @desired_properties[:Action]
          }
        ]
      }.to_json
    end

    def create_resource
      build_role_policy_document
      @aws_client.create_role(role_name: @desired_properties[:role_name], assume_role_policy_document: @desired_properties[:assume_role_policy_document])
    end

    def delete_resource
      detach_policies
      @aws_client.delete_role(role_name: @desired_properties[:role_name])
    end

    def process_diff(diff)
      diff.each do |key, val|
        if keys(:update_policy).include?(key)
          detach_policies
          val.each do |policy_arn|
            @aws_client.attach_role_policy(role_name: @desired_properties[:role_name], policy_arn: policy_arn)
          end
        end
      end
    end

    def detach_policies
      policies = @aws_client.list_attached_role_policies(role_name: @desired_properties[:role_name]).attached_policies
      policies.each do |policy|
        @aws_client.detach_role_policy(role_name: @desired_properties[:role_name], policy_arn: policy.policy_arn)
      end
    end

  end
end
