require 'account_controller'
require 'json'

class RedmineOauthController < AccountController
  include Helpers::MailHelper
  include Helpers::Checker
  def oauth_google
    if Setting.plugin_redmine_omniauth_google["oauth_authentification"]
      session[:back_url] = params[:back_url]
      redirect_to oauth_client.auth_code.authorize_url(:redirect_uri => oauth_google_callback_url, :scope => scopes)
    else
      password_authentication
    end
  end

  def oauth_google_callback
    if params[:error]
      flash[:error] = l(:notice_access_denied)
      redirect_to signin_path
    else
      token = oauth_client.auth_code.get_token(params[:code], :redirect_uri => oauth_google_callback_url)
      result = token.get('https://www.googleapis.com/oauth2/v1/userinfo')
      info = JSON.parse(result.body)
      if info && info["verified_email"]
        if allowed_domain_for?(info["email"])
          try_to_login info
        else
          flash[:error] = l(:notice_domain_not_allowed, :domain => parse_email(info["email"])[:domain])
          redirect_to signin_path
        end
      else
        flash[:error] = l(:notice_unable_to_obtain_google_credentials)
        redirect_to signin_path
      end
    end
  end

  def try_to_login info
    params[:back_url] = session.delete(:back_url)
    userEmail = info["email"]
    user = User.where(login: userEmail).first
    user = User.having_mail(userEmail).first if not user
    if user
      # User found, log in.
      user.update_column(:last_login_on, Time.now)
      user.active? ? successful_authentication(user): account_pending(user)
    else
      # Self-registration off
      redirect_to(home_url) && return unless Setting.self_registration?
      # Create on the fly
      firstname, lastname = info["name"].split(' ') unless info['name'].nil?
      firstname ||= info[:given_name]
      lastname ||= info[:family_name]
      user = User.new
      user.mail = userEmail
      user.login = userEmail
      user.firstname = firstname
      user.lastname = lastname
      user.random_password
      user.register

      case Setting.self_registration
      when '1'
        register_by_email_activation(user) do
          onthefly_creation_failed(user)
        end
      when '3'
        register_automatically(user) do
          onthefly_creation_failed(user)
        end
      else
        hd = info["hd"]
        if hd.present? && trusted_domain?(hd)
          user.activate
          if user.save
            user_mapped_groups(hd).each { |g| g.users << user }
            flash[:notice] = l(:notice_account_activated)
            redirect_to(my_account_path)
          else
            onthefly_creation_failed(user)
          end
        else
          register_manually_by_administrator(user) do
            onthefly_creation_failed(user)
          end
        end
      end
    end
  end

  def oauth_client
    @client ||= OAuth2::Client.new(settings["client_id"], settings["client_secret"],
      :site => 'https://accounts.google.com',
      :authorize_url => '/o/oauth2/auth',
      :token_url => '/o/oauth2/token')
  end

  def settings
    @settings ||= Setting.plugin_redmine_omniauth_google
  end

  def scopes
    'https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile'
  end
end
