# Security

## meson

create a file with the name `vrocksecurity.wrap`
and fill it with the following content

```text
[wrap-git]
url=https://github.com/Visual-Rock/vrock.security
revision=head
depth=1

[provide]
vrocksecurity=vrocksecurity_dep
```