# Local Test Environment for hms-creds-conrol

## Prep

1. Collect smd data from real hardware
    1. ssh to system
        ```
        ssh root@shasta_system
        ```
    2. save smd postgres data
        ```
        kubectl exec -it -n services -c postgres cray-smd-postgres-0 -- pg_dump -U postgres -d hmsds -n public > /var/tmp/smd.sql
        ```
    3. copy smd.sql file back do developement system
        ```
        scp root@shasta_system:/var/tmp/smd.sql /var/tmp/smd.sql
        ```
## Start test containers      

1. start docker compose env
    ```
    docker-compose -f docker-compose.devel.yaml up
    ```
2. import smd data
    ```
    docker cp /var/tmp/smd.sql hms-creds-control_hmsds-postgres_1:/var/tmp/smd.sql
    docker exec -it hms-creds-control_hmsds-postgres_1 sh -c 'psql postgresql://hmsdsuser:hmsdsuser@hmsds-postgres:5432/hmsds < /var/tmp/smd.sql'
    ```
    Note there will be errors from psql about relations and other items already existing. This is expected. It happens because the database has already been initialized.

## build docker image
```
make image
```

## test hms-creds-control
```
docker run -it --rm --network host \
    -e VAULT_BASE_PATH='' \
    -e VAULT_ADDR='http://localhost:8200' \
    -e VAULT_TOKEN='hms' \
    -e CRAY_VAULT_AUTH_PATH=auth/token/create \
    -e CRAY_VAULT_ROLE_FILE=configs/namespace \
    -e CRAY_VAULT_JWT_FILE=configs/token \
    -e VAULT_KEYPATH='hms-creds' \
    -e USER_MODIFICATIONS_ENABLED='true' \
    -e XNAME_INCLUDE='.*' \
    -e XNAME_EXCLUDE='' \
    -e USERNAME_INCLUDE='.*' \
    -e USERNAME_EXCLUDE='' \
    -e PASSWORD_LENGTH='15' \
    -e PASSWORD_POSSIBLE_CHARACTERS='0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ' \
    -w / \
    -v $(pwd)/testing/configs:/configs \
    hms-creds-control:$(cat .version) \
    sh -c "creds-control --hsm_url='http://localhost:27779'"
```


