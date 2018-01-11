module ApplicationHelper
  def current_url_no_params
    url_for only_path: false
  end
end
