# Mailcow Terraform Deployment on GCP

provider "google" {
  project = "mailcow-mail"
  region  = "asia-southeast2"
}

resource "google_compute_network" "mailcow_vpc" {
  name                    = "mailcow-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "mailcow_subnet" {
  name          = "sub-mailcow"
  region        = "asia-southeast2"
  network       = google_compute_network.mailcow_vpc.id
  ip_cidr_range = "10.32.1.0/24"
}

resource "google_compute_firewall" "allow_mail" {
  project = "mailcow-mail"
  name    = "allow-mailcow"
  network = google_compute_network.mailcow_vpc.name

  allow {
    protocol = "tcp"
    ports    = ["25", "80", "443", "110", "143", "465", "587", "993", "995", "50080", "50443"]
  }
  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_firewall" "allow_internal" {
  project = "mailcow-mail"
  name    = "allow-internal"
  network = google_compute_network.mailcow_vpc.name

  allow {
    protocol = "tcp"
    ports    = ["3306", "6379"]
  }
  source_ranges = ["10.32.1.0/24"]
}

resource "google_compute_address" "static_ip" {
  name = "mailcow-ip"
}

resource "google_compute_instance" "mailcow" {
  name         = "mailcow-server"
  machine_type = "e2-standard-4"
  zone         = "asia-southeast2-a"

  allow_stopping_for_update = true

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = 100
      type  = "pd-ssd"
    }
  }

  network_interface {
    network    = google_compute_network.mailcow_vpc.self_link
    subnetwork = google_compute_subnetwork.mailcow_subnet.self_link

    access_config {
      nat_ip = google_compute_address.static_ip.address
    }
  }

  metadata_startup_script = <<-EOT
    #!/bin/bash
    apt update && apt upgrade -y
    apt install -y git docker docker-compose
    git clone https://github.com/mailcow/mailcow-dockerized.git /opt/mailcow
    cd /opt/mailcow
    cp mailcow.conf.example mailcow.conf
    sed -i "s/MAILCOW_HOSTNAME=/MAILCOW_HOSTNAME=xmail.kftd.co.id/" mailcow.conf
    sed -i "s/HTTP_BIND=0.0.0.0:8080/HTTP_BIND=0.0.0.0:50080/" mailcow.conf
    sed -i "s/HTTPS_BIND=0.0.0.0:8443/HTTPS_BIND=0.0.0.0:50443/" mailcow.conf
    ./generate_config.sh
    docker-compose pull
    docker-compose up -d
  EOT
}

resource "google_compute_global_address" "lb_ip" {
  name = "mailcow-lb-ip"
}

resource "google_compute_backend_service" "mailcow_backend" {
  name                  = "mailcow-backend"
  health_checks         = [google_compute_health_check.mailcow_health.id]
  load_balancing_scheme = "EXTERNAL"
}

resource "google_compute_health_check" "mailcow_health" {
  name = "mailcow-health-check"

  http_health_check {
    port = "443"
  }
}

resource "google_compute_url_map" "mailcow_url_map" {
  name = "mailcow-url-map"

  default_service = google_compute_backend_service.mailcow_backend.id
}

resource "google_compute_target_https_proxy" "mailcow_proxy" {
  name             = "mailcow-proxy"
  url_map         = google_compute_url_map.mailcow_url_map.id
  ssl_certificates = [google_compute_managed_ssl_certificate.mailcow_new_cert.id]
}

resource "google_compute_global_forwarding_rule" "mailcow_forwarding_rule" {
  name       = "mailcow-forwarding-rule"
  target     = google_compute_target_https_proxy.mailcow_proxy.id
  port_range = "443"
  ip_address = google_compute_global_address.lb_ip.address
}

resource "google_compute_security_policy" "mailcow_cloud_armor" {
  name = "mailcow-security-policy"

  # Custom deny rule (example: blocking specific IPs)
  rule {
    action   = "deny(403)"
    priority = 900
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["1.2.3.4/32"]
      }
    }
  }

  # Required default rule (must have match condition `*` and be at priority 2147483647)
  rule {
    action   = "allow"
    priority = 2147483647
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
  }
}

resource "google_compute_managed_ssl_certificate" "mailcow_new_cert" {
  name = "mailcow-new-cert"
  managed {
    domains = ["xmail.kftd.co.id", "email.kftd.co.id"]
  }
}