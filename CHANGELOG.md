# 0.3.0

- Added lifetime parameter to `HttpMethod`
- Changed `HttpMethod::OTHER(&'static str)` to `HttpMethod::OTHER(Cow<'a, str>)`
- Added unit tests
- Converted one Into impl to From

# 0.2.4

- Update dependencies

