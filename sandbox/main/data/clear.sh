main() {
    rm -rf ./pcaps/*
    rm -rf ./results/*
    rm -rf ./figures/*

    echo "Data cleared."
}

main "$@"