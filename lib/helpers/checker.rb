module Helpers
  module Checker
    def allowed_domain_for? email
      allowed_domains = Setting.plugin_redmine_omniauth_google["allowed_domains"]
      return unless allowed_domains
      allowed_domains = allowed_domains.split
      return true if allowed_domains.empty?
      allowed_domains.index(parse_email(email)[:domain])
    end

    def trusted_domain?(hd)
      domains = Setting.plugin_redmine_omniauth_google["trusted_domains"].try(:split)
      return false if domains.blank?
      domains.index(hd)
    end

    def user_mapped_groups(hd)
      setting = Setting.plugin_redmine_omniauth_google["group_mapping"]
      return [] if setting.blank?
      mapping = Hash[setting.split.map { |x| x.split(":") }]
      ids = mapping[hd].try(:split, ",") || []
      ids.map { |id| Group.find(id) }
    end
  end
end
