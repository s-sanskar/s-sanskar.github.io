FROM ruby:3.1

# Install dependencies
RUN apt-get update -qq && apt-get install -y \
    build-essential \
    nodejs \
    yarn

# Set working directory
WORKDIR /app

# Copy Gemfile and Gemfile.lock
COPY Gemfile Gemfile.lock ./

# Install gems
RUN bundle install

# Copy the rest of the application
COPY . .

# Build the site
RUN bundle exec jekyll build

# Expose port 4000
EXPOSE 4000

# Run Jekyll server
CMD ["bundle", "exec", "jekyll", "serve", "--host", "0.0.0.0"]