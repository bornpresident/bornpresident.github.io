# frozen_string_literal: true
source "https://rubygems.org"

gemspec

group :test do
  gem "html-proofer", "~> 3.18"
end

# Windows and JRuby does not include zoneinfo files, so bundle the tzinfo-data gem
# and associated library.
platforms :mingw, :x64_mingw, :mswin, :jruby do
  gem "tzinfo", ">= 1", "< 3"
  gem "tzinfo-data"
  gem "sassc", "~> 2.4"  # For better Sass compilation performance on Windows
  gem "eventmachine", "~> 1.2"  # Helps with Windows live reloading
end

# Lock `http_parser.rb` gem to `v0.6.x` on JRuby builds since newer versions of the gem
# do not have a Java counterpart.
gem "http_parser.rb", "~> 0.6.0", :platforms => [:jruby]

# Lock jekyll-sass-converter to 2.x on Linux-musl
if RUBY_PLATFORM =~ /linux-musl/
  gem "jekyll-sass-converter", "~> 2.0"
end

# Use webrick since it's no longer bundled with Ruby 3+
gem "webrick", "~> 1.8"

# Required for Ruby 3.4.0 compatibility
gem "base64", "~> 0.2.0"
gem "bigdecimal", "~> 3.1"# frozen_string_literal: true
source "https://rubygems.org"

gemspec

group :test do
  gem "html-proofer", "~> 3.18"
end

# Windows and JRuby does not include zoneinfo files, so bundle the tzinfo-data gem
# and associated library.
platforms :mingw, :x64_mingw, :mswin, :jruby do
  gem "tzinfo", ">= 1", "< 3"
  gem "tzinfo-data"
  gem "sassc", "~> 2.4"  # For better Sass compilation performance on Windows
  gem "eventmachine", "~> 1.2"  # Helps with Windows live reloading
end

# Lock `http_parser.rb` gem to `v0.6.x` on JRuby builds since newer versions of the gem
# do not have a Java counterpart.
gem "http_parser.rb", "~> 0.6.0", :platforms => [:jruby]

# Lock jekyll-sass-converter to 2.x on Linux-musl
if RUBY_PLATFORM =~ /linux-musl/
  gem "jekyll-sass-converter", "~> 2.0"
end

# Use webrick since it's no longer bundled with Ruby 3+
gem "webrick", "~> 1.8"

# Required for Ruby 3.4.0 compatibility
gem "base64", "~> 0.2.0"
gem "bigdecimal", "~> 3.1"
gem 'csv'
gem 'logger'
