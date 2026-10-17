# escape=`
# A Windows-style Dockerfile using the backtick escape character. Under the
# `# escape=` directive a trailing backslash is a literal path character, not a
# line continuation, so `WORKDIR C:\app\` must not swallow the EXPOSE below.
FROM mcr.microsoft.com/windows/servercore:ltsc2022
WORKDIR C:\app\
ENV APP_HOME=C:\app
EXPOSE 8080
USER ContainerUser
ENTRYPOINT ["app.exe"]
