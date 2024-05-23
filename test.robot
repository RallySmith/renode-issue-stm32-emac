*** Settings ***
Suite Setup                   Setup
Suite Teardown                Teardown
Test Setup                    Reset Emulation
Test Teardown                 Custom Test Teardown
Resource                      ${RENODEKEYWORDS}


*** Keywords ***
Custom Test Teardown
    Log To Console            !!!! Custom Test Teardown !!!! since normal teardown hangs
    #Test Teardown
    Log To Console            !!!! Completed !!!!


*** Variables ***
${SCRIPT}                     ${CURDIR}/test.resc
${UARTS}                      sysbus.usart3
${UARTC}                      sysbus.usart6


*** Keywords ***
Load Script
    Execute Script            ${SCRIPT}
    Create Log Tester         1

*** Test Cases ***
Should Run Test Case
    [Timeout]                 20 seconds
    Load Script

    ${us}=                    Create Terminal Tester    ${UARTS}     machine=server
    ${uc}=                    Create Terminal Tester    ${UARTC}     machine=client

    Start Emulation

    Wait For Line On Uart     EXIT:<done>                                                                              testerId=${us}
    Wait For Line On Uart     EXIT:<done>                                                                              testerId=${uc}
