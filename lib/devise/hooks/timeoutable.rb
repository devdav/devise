# Each time a record is set we check whether its session has already timed out
# or not, based on last request time. If so, the record is logged out and
# redirected to the sign in page. Also, each time the request comes and the
# record is set, we set the last request time inside its scoped session to
# verify timeout in the following request.
Warden::Manager.after_set_user do |record, warden, options|
  scope = options[:scope]
  env   = warden.request.env

  if record && record.respond_to?(:timedout?) && warden.authenticated?(scope) && options[:store] != false
    last_request_at = warden.session(scope)['last_request_at']

    if record.timedout?(last_request_at) && !env['devise.skip_timeout']
      warden.logout(scope)
      if record.respond_to?(:expire_auth_token_on_timeout) && record.expire_auth_token_on_timeout
        record.reset_authentication_token!
      end
      throw :warden, :scope => scope, :message => :timeout
    end

    # DE 2011/08/15 PATCH: only update the session for non-'silent', non-xhr requests
    if !env['devise.skip_trackable'] && ((!warden.request.xhr? || warden.request.params[:silent].blank?) rescue true)
      warden.session(scope)['last_request_at'] = Time.now.utc
    end
  end
end
