
// Description: Java 25 Factory service implementation for SecSysGrpMemb JPA objects

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
 *	Java 25 Factory service implementation for SecSysGrpMemb JPA objects.
 */
public class CFSecJpaSecSysGrpMembFactoryService
    implements ICFSecSecSysGrpMembFactory
{
    public CFSecJpaSecSysGrpMembFactoryService() { }

    @Override
    public ICFSecSecSysGrpMembPKey newPKey() {
        ICFSecSecSysGrpMembPKey pkey = new CFSecJpaSecSysGrpMembPKey();
        return( pkey );
    }

	public CFSecJpaSecSysGrpMembPKey ensurePKey(ICFSecSecSysGrpMembPKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecSysGrpMembPKey) {
			return( (CFSecJpaSecSysGrpMembPKey)key );
		}
		else {
			CFSecJpaSecSysGrpMembPKey mapped = new CFSecJpaSecSysGrpMembPKey();
			mapped.setRequiredSecSysGrpId( key.getRequiredSecSysGrpId() );
			mapped.setRequiredLoginId( key.getRequiredLoginId() );
			return( mapped );
		}
	}

    @Override
    public ICFSecSecSysGrpMembHPKey newHPKey() {
        ICFSecSecSysGrpMembHPKey hpkey = new CFSecJpaSecSysGrpMembHPKey();
        return( hpkey );
    }

	public CFSecJpaSecSysGrpMembHPKey ensureHPKey(ICFSecSecSysGrpMembHPKey key) {
		if (key == null) {
			return( null );
		}
		else if( key instanceof CFSecJpaSecSysGrpMembHPKey) {
			return( (CFSecJpaSecSysGrpMembHPKey)key );
		}
		else {
			CFSecJpaSecSysGrpMembHPKey mapped = new CFSecJpaSecSysGrpMembHPKey();
			mapped.setAuditClusterId(key.getAuditClusterId());
			mapped.setAuditActionId(key.getAuditActionId());
			mapped.setAuditSessionId(key.getAuditSessionId());
			mapped.setAuditStamp(key.getAuditStamp());
			mapped.setRequiredSecSysGrpId( key.getRequiredSecSysGrpId() );
			mapped.setRequiredLoginId( key.getRequiredLoginId() );
			return( mapped );
		}
	}

    @Override
    public ICFSecSecSysGrpMembBySysGrpIdxKey newBySysGrpIdxKey() {
		ICFSecSecSysGrpMembBySysGrpIdxKey key = new CFSecJpaSecSysGrpMembBySysGrpIdxKey();
	return( key );
    }

	public CFSecJpaSecSysGrpMembBySysGrpIdxKey ensureBySysGrpIdxKey(ICFSecSecSysGrpMembBySysGrpIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecSysGrpMembBySysGrpIdxKey) {
			return( (CFSecJpaSecSysGrpMembBySysGrpIdxKey)key );
		}
		else {
			CFSecJpaSecSysGrpMembBySysGrpIdxKey mapped = new CFSecJpaSecSysGrpMembBySysGrpIdxKey();
			mapped.setRequiredSecSysGrpId( key.getRequiredSecSysGrpId() );
			return( mapped );
		}
	}

    @Override
    public ICFSecSecSysGrpMembByLoginIdxKey newByLoginIdxKey() {
		ICFSecSecSysGrpMembByLoginIdxKey key = new CFSecJpaSecSysGrpMembByLoginIdxKey();
	return( key );
    }

	public CFSecJpaSecSysGrpMembByLoginIdxKey ensureByLoginIdxKey(ICFSecSecSysGrpMembByLoginIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaSecSysGrpMembByLoginIdxKey) {
			return( (CFSecJpaSecSysGrpMembByLoginIdxKey)key );
		}
		else {
			CFSecJpaSecSysGrpMembByLoginIdxKey mapped = new CFSecJpaSecSysGrpMembByLoginIdxKey();
			mapped.setRequiredLoginId( key.getRequiredLoginId() );
			return( mapped );
		}
	}

    @Override
    public ICFSecSecSysGrpMemb newRec() {
        ICFSecSecSysGrpMemb rec = new CFSecJpaSecSysGrpMemb();
        return( rec );
    }

	public CFSecJpaSecSysGrpMemb ensureRec(ICFSecSecSysGrpMemb rec) {
		if( rec == null ) {
			return( null );
		}
		else if (rec instanceof CFSecJpaSecSysGrpMemb) {
			return( (CFSecJpaSecSysGrpMemb)rec );
		}
		else {
			switch(rec.getClassCode()) {
				case ICFSecSecSysGrpMemb.CLASS_CODE: {
					CFSecJpaSecSysGrpMemb mapped = new CFSecJpaSecSysGrpMemb();
					mapped.set(rec);
					return( mapped ); }
				default:
					throw new CFLibUnsupportedClassException(getClass(), "ensureRec",
						"Unsupported class code " + rec.getClassCode() + " is not a derivative of CFSecSecSysGrpMemb",
						"Unsupported class code " + rec.getClassCode() + " is not a derivative of CFSecSecSysGrpMemb");
			}
		}
	}

    @Override
    public ICFSecSecSysGrpMembH newHRec() {
        ICFSecSecSysGrpMembH hrec = new CFSecJpaSecSysGrpMembH();
        return( hrec );
    }

	public CFSecJpaSecSysGrpMembH ensureHRec(ICFSecSecSysGrpMembH hrec) {
		if( hrec == null ) {
			return( null );
		}
		else if (hrec instanceof CFSecJpaSecSysGrpMembH) {
			return( (CFSecJpaSecSysGrpMembH)hrec );
		}
		else {
			switch(hrec.getClassCode()) {
				case ICFSecSecSysGrpMemb.CLASS_CODE: {
					CFSecJpaSecSysGrpMembH mapped = new CFSecJpaSecSysGrpMembH();
					mapped.set(hrec);
					return( mapped ); }
				default:
					throw new CFLibUnsupportedClassException(getClass(), "ensureHRec",
						"Unsupported class code " + hrec.getClassCode() + " is not a derivative of CFSecSecSysGrpMemb",
						"Unsupported class code " + hrec.getClassCode() + " is not a derivative of CFSecSecSysGrpMemb");
			}
		}
	}
}
