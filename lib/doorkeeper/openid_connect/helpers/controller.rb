module Doorkeeper
  module OpenidConnect
    module Helpers
      module Controller
        private

        def authenticate_resource_owner!
          super.tap do |owner|
            next unless pre_auth.scopes.include? 'openid'

            handle_prompt_param!(owner)
            handle_max_age_param!(owner)
          end
        rescue Errors::OpenidConnectError => exception
          # clear the previous response body to avoid a DoubleRenderError
          self.response_body = nil

          # FIXME: workaround for Rails 5, see https://github.com/rails/rails/issues/25106
          @_response_body = nil

          error = ::Doorkeeper::OAuth::ErrorResponse.new(name: exception.error_name)
          response.headers.merge!(error.headers)
          render json: error.body, status: error.status
        end

        def handle_prompt_param!(owner)
          prompt_values ||= params[:prompt].to_s.split(/ +/).uniq

          prompt_values.each do |prompt|
            case prompt
            when 'none' then
              raise Errors::InvalidRequest if (prompt_values - [ 'none' ]).any?
              raise Errors::LoginRequired unless owner
              raise Errors::ConsentRequired unless matching_token_for_resource_owner(owner)
            when 'login' then
              reauthenticate_resource_owner(owner) if owner
            when 'consent' then
              matching_token_for_resource_owner(owner).try(:destroy)
            when 'select_account' then
              # TODO: let the user implement this
              raise Errors::AccountSelectionRequired
            else
              raise Errors::InvalidRequest
            end
          end
        end

        def handle_max_age_param!(owner)
          max_age = params[:max_age].to_i
          return unless max_age > 0 && owner

          auth_time = instance_exec owner,
            &Doorkeeper::OpenidConnect.configuration.auth_time_from_resource_owner

          if !auth_time || (Time.zone.now - auth_time) > max_age
            reauthenticate_resource_owner(owner)
          end
        end

        def reauthenticate_resource_owner(owner)
          return_to = URI.parse(request.path)
          return_to.query = request.query_parameters.tap do |params|
            params['prompt'] = params['prompt'].to_s.sub(/\blogin\s*\b/, '').strip
            params.delete('prompt') if params['prompt'].blank?
          end.to_query

          instance_exec owner, return_to.to_s,
            &Doorkeeper::OpenidConnect.configuration.reauthenticate_resource_owner

          raise Errors::LoginRequired unless performed?
        end

        def matching_token_for_resource_owner(owner)
          AccessToken.matching_token_for(pre_auth.client, owner.id, pre_auth.scopes)
        end
      end
    end
  end

  Helpers::Controller.send :prepend, OpenidConnect::Helpers::Controller
end
