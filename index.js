const SQL_commands = ['SELECT',';--','&','-','|','TRUNCATE','%', 'UNION','DROP','CREATE','INTO','COPY','*',"'"]
const XSS_commands = ['<','>','script','javascript',':','document','location','html','"','/','+']

function validate(input){
    sql_report= validateSQLInjection(input)

    xss_report= validateXSS(input)
    output_status = sql_report.status +" "+ xss_report.status
    return {status: output_status, condition: !(sql_report.condition || xss_report.condition)}
}
    
function validateXSS(data){
    for(let i = 0 ; i < XSS_commands.length;i++){
        if(data.toUpperCase().includes(XSS_commands[i].toUpperCase())){
            return {status: 'Cross-site Scripting: Vulnerable', condition: true}
        }
    }
    return {status: 'Cross-site Scripting: NOT Vulnerable', condition: false }   
}

function validateSQLInjection(data){
    for(let i = 0 ; i < SQL_commands.length;i++){
        if(data.toUpperCase().includes(SQL_commands[i].toUpperCase())){
            return {status: 'SQL Injection: Vulnerable', condition: true}
        }
    }
    return {status: 'SQL Injection: NOT Vulnerable', condition: false}    
}
