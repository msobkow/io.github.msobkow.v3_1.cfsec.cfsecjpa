
// Description: Java 25 Factory service implementation for SecUserPassword JPA objects

/*
 *	server.markhome.mcf.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow mark.sobkow@gmail.com
 *	
 *	These files are part of Mark's Code Fractal CFSec.
 *	
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *	
 *	http://www.apache.org/licenses/LICENSE-2.0
 *	
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 *	
 */

package server.markhome.mcf.v3_1.cfsec.cfsec.jpa;

import java.lang.reflect.*;
import java.net.*;
import java.rmi.*;
import java.sql.*;
import java.text.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.text.StringEscapeUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import server.markhome.mcf.v3_1.cflib.*;
import server.markhome.mcf.v3_1.cflib.dbutil.*;
import server.markhome.mcf.v3_1.cflib.keyhash.*;
import server.markhome.mcf.v3_1.cfsec.cfsec.*;

/*
 *	Java 25 Factory service implementation for SecUserPassword JPA objects.
 */
public class CFSecJpaSecUserPasswordFactoryService
    implements ICFSecSecUserPasswordFactory
{
    public CFSecJpaSecUserPasswordFactoryService() { }

    @Override
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
    public ICFSecSecUserPasswordHPKey newHPKey() {
        ICFSecSecUserPasswordHPKey hpkey = new CFSecJpaSecUserPasswordHPKey();
        return( hpkey );
    }

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecUserPasswordHPKey ensureHPKey(ICFSecSecUserPasswordHPKey key) {
		if (key == null) {
			return( null );
		}
		else if( key instanceof CFSecJpaSecUserPasswordHPKey) {
			return( (CFSecJpaSecUserPasswordHPKey)key );
		}
		else {
			CFSecJpaSecUserPasswordHPKey mapped = new CFSecJpaSecUserPasswordHPKey();
			mapped.setAuditClusterId(key.getAuditClusterId());
			mapped.setAuditActionId(key.getAuditActionId());
			mapped.setAuditSessionId(key.getAuditSessionId());
			mapped.setAuditStamp(key.getAuditStamp());
			mapped.setRequiredSecUserId( key.getRequiredSecUserId() );
			return( mapped );
		}
	}

    @Override
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
    public ICFSecSecUserPasswordBySetStampIdxKey newBySetStampIdxKey() {
		ICFSecSecUserPasswordBySetStampIdxKey key = new CFSecJpaSecUserPasswordBySetStampIdxKey();
	return( key );
    }

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecUserPasswordBySetStampIdxKey ensureBySetStampIdxKey(ICFSecSecUserPasswordBySetStampIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecUserPasswordBySetStampIdxKey) {
			return( (CFSecJpaSecUserPasswordBySetStampIdxKey)key );
		}
		else {
			CFSecJpaSecUserPasswordBySetStampIdxKey mapped = new CFSecJpaSecUserPasswordBySetStampIdxKey();
			mapped.setRequiredPWSetStamp( key.getRequiredPWSetStamp() );
			return( mapped );
		}
	}

    @Override
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
    public ICFSecSecUserPassword newRec() {
        ICFSecSecUserPassword rec = new CFSecJpaSecUserPassword();
        return( rec );
    }

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecUserPassword ensureRec(ICFSecSecUserPassword rec) {
		if( rec == null ) {
			return( null );
		}
		else if (rec instanceof CFSecJpaSecUserPassword) {
			return( (CFSecJpaSecUserPassword)rec );
		}
		else {
			switch(rec.getClassCode()) {
				case ICFSecSecUserPassword.CLASS_CODE: {
					CFSecJpaSecUserPassword mapped = new CFSecJpaSecUserPassword();
					mapped.set(rec);
					return( mapped ); }
				default:
					throw new CFLibUnsupportedClassException(getClass(), "ensureRec",
						"Unsupported class code " + rec.getClassCode() + " is not a derivative of CFSecSecUserPassword",
						"Unsupported class code " + rec.getClassCode() + " is not a derivative of CFSecSecUserPassword");
			}
		}
	}

    @Override
    public ICFSecSecUserPasswordH newHRec() {
        ICFSecSecUserPasswordH hrec = new CFSecJpaSecUserPasswordH();
        return( hrec );
    }

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecUserPasswordH ensureHRec(ICFSecSecUserPasswordH hrec) {
		if( hrec == null ) {
			return( null );
		}
		else if (hrec instanceof CFSecJpaSecUserPasswordH) {
			return( (CFSecJpaSecUserPasswordH)hrec );
		}
		else {
			switch(hrec.getClassCode()) {
				case ICFSecSecUserPassword.CLASS_CODE: {
					CFSecJpaSecUserPasswordH mapped = new CFSecJpaSecUserPasswordH();
					mapped.set(hrec);
					return( mapped ); }
				default:
					throw new CFLibUnsupportedClassException(getClass(), "ensureHRec",
						"Unsupported class code " + hrec.getClassCode() + " is not a derivative of CFSecSecUserPassword",
						"Unsupported class code " + hrec.getClassCode() + " is not a derivative of CFSecSecUserPassword");
			}
		}
	}
}
