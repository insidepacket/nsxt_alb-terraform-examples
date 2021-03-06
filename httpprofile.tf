resource "avi_applicationprofile" "test1000_httpprofile" {
    http_profile {
      max_keepalive_requests = 100
      enable_chunk_merge = true
      max_rps_uri = 0
      client_header_timeout = 10000
      fwd_close_hdr_for_bound_connections = true
      keepalive_header = false
      max_rps_cip_uri = 0
      x_forwarded_proto_enabled = true
      connection_multiplexing_enabled = true
      websockets_enabled = true
      enable_request_body_metrics = false
      max_http2_empty_data_frames_per_connection = 1000
      http2_enabled = false
      enable_request_body_buffering = false
      hsts_enabled = true
      xff_enabled = true
      reset_conn_http_on_ssl_port = false
      disable_keepalive_posts_msie6 = true
      keepalive_timeout = 30000
      ssl_client_certificate_mode = "SSL_CLIENT_CERTIFICATE_NONE"
      http_to_https = true
      disable_sni_hostname_check = false
      respond_with_100_continue = true
      max_bad_rps_cip_uri = 0
      httponly_enabled = true
      hsts_max_age = 365
      max_bad_rps_cip = 0
      server_side_redirect_to_https = true
      client_max_header_size = 12
      client_max_request_size = 48
      max_http2_control_frames_per_connection = 1000
      max_http2_concurrent_streams_per_connection = 128
      max_rps_unknown_uri = 0
      hsts_subdomains_enabled = true
      allow_dots_in_header_name = false
      max_http2_queued_frames_to_client_per_connection = 1000
      post_accept_timeout = 30000
      secure_cookie_enabled = true
      max_response_headers_size = 48
      xff_alternate_name = "X-Forwarded-For"
      max_rps_cip = 0
      client_max_body_size = 0
      enable_fire_and_forget = false
      max_rps_unknown_cip = 0
      client_body_timeout = 30000
      max_bad_rps_uri = 0
      use_app_keepalive_timeout = false
    }
    preserve_client_port = false
    preserve_client_ip = false
    name = "test1000_httpprofile"
    type = "APPLICATION_PROFILE_TYPE_HTTP"
  }
