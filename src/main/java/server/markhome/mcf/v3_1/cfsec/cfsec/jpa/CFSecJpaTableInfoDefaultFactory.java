
// Description: Java 25 JPA Default Factory implementation for TableInfo.

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
import server.markhome.mcf.v3_1.cflib.*;
import server.markhome.mcf.v3_1.cflib.dbutil.*;
import server.markhome.mcf.v3_1.cfsec.cfsec.*;

/*
 *	CFSecTableInfoFactory JPA implementation for TableInfo
 */
public class CFSecJpaTableInfoDefaultFactory
    implements ICFSecTableInfoFactory
{
    public CFSecJpaTableInfoDefaultFactory() {
    }

    @Override
    public ICFSecTableInfoHPKey newHPKey() {
        ICFSecTableInfoHPKey hpkey =
            new CFSecJpaTableInfoHPKey();
        return( hpkey );
    }

	public CFSecJpaTableInfoHPKey ensureHPKey(ICFSecTableInfoHPKey key) {
		if (key == null) {
			return( null );
		}
		else if( key instanceof CFSecJpaTableInfoHPKey) {
			return( (CFSecJpaTableInfoHPKey)key );
		}
		else {
			CFSecJpaTableInfoHPKey mapped = new CFSecJpaTableInfoHPKey();
			mapped.setAuditClusterId(key.getAuditClusterId());
			mapped.setAuditActionId(key.getAuditActionId());
			mapped.setAuditSessionId(key.getAuditSessionId());
			mapped.setAuditStamp(key.getAuditStamp());
			mapped.setRequiredTableInfoId( key.getRequiredTableInfoId() );
			return( mapped );
		}
	}

    @Override
    public ICFSecTableInfoByTableNameIdxKey newByTableNameIdxKey() {
	ICFSecTableInfoByTableNameIdxKey key =
            new CFSecJpaTableInfoByTableNameIdxKey();
	return( key );
    }

	public CFSecJpaTableInfoByTableNameIdxKey ensureByTableNameIdxKey(ICFSecTableInfoByTableNameIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaTableInfoByTableNameIdxKey) {
			return( (CFSecJpaTableInfoByTableNameIdxKey)key );
		}
		else {
			CFSecJpaTableInfoByTableNameIdxKey mapped = new CFSecJpaTableInfoByTableNameIdxKey();
			mapped.setRequiredTableName( key.getRequiredTableName() );
			return( mapped );
		}
	}

    @Override
    public ICFSecTableInfoBySuperNameIdxKey newBySuperNameIdxKey() {
	ICFSecTableInfoBySuperNameIdxKey key =
            new CFSecJpaTableInfoBySuperNameIdxKey();
	return( key );
    }

	public CFSecJpaTableInfoBySuperNameIdxKey ensureBySuperNameIdxKey(ICFSecTableInfoBySuperNameIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaTableInfoBySuperNameIdxKey) {
			return( (CFSecJpaTableInfoBySuperNameIdxKey)key );
		}
		else {
			CFSecJpaTableInfoBySuperNameIdxKey mapped = new CFSecJpaTableInfoBySuperNameIdxKey();
			mapped.setOptionalSuperName( key.getOptionalSuperName() );
			return( mapped );
		}
	}

    @Override
    public ICFSecTableInfoBySchemaNameIdxKey newBySchemaNameIdxKey() {
	ICFSecTableInfoBySchemaNameIdxKey key =
            new CFSecJpaTableInfoBySchemaNameIdxKey();
	return( key );
    }

	public CFSecJpaTableInfoBySchemaNameIdxKey ensureBySchemaNameIdxKey(ICFSecTableInfoBySchemaNameIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaTableInfoBySchemaNameIdxKey) {
			return( (CFSecJpaTableInfoBySchemaNameIdxKey)key );
		}
		else {
			CFSecJpaTableInfoBySchemaNameIdxKey mapped = new CFSecJpaTableInfoBySchemaNameIdxKey();
			mapped.setRequiredSchemaName( key.getRequiredSchemaName() );
			return( mapped );
		}
	}

    @Override
    public ICFSecTableInfoBySchemaBkCodeIdxKey newBySchemaBkCodeIdxKey() {
	ICFSecTableInfoBySchemaBkCodeIdxKey key =
            new CFSecJpaTableInfoBySchemaBkCodeIdxKey();
	return( key );
    }

	public CFSecJpaTableInfoBySchemaBkCodeIdxKey ensureBySchemaBkCodeIdxKey(ICFSecTableInfoBySchemaBkCodeIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaTableInfoBySchemaBkCodeIdxKey) {
			return( (CFSecJpaTableInfoBySchemaBkCodeIdxKey)key );
		}
		else {
			CFSecJpaTableInfoBySchemaBkCodeIdxKey mapped = new CFSecJpaTableInfoBySchemaBkCodeIdxKey();
			mapped.setRequiredSchemaName( key.getRequiredSchemaName() );
			mapped.setRequiredBackingClassCode( key.getRequiredBackingClassCode() );
			return( mapped );
		}
	}

    @Override
    public ICFSecTableInfoBySchemaRTCodeIdxKey newBySchemaRTCodeIdxKey() {
	ICFSecTableInfoBySchemaRTCodeIdxKey key =
            new CFSecJpaTableInfoBySchemaRTCodeIdxKey();
	return( key );
    }

	public CFSecJpaTableInfoBySchemaRTCodeIdxKey ensureBySchemaRTCodeIdxKey(ICFSecTableInfoBySchemaRTCodeIdxKey key) {
		if (key == null) {
			return( null );
		}
		else if (key instanceof CFSecJpaTableInfoBySchemaRTCodeIdxKey) {
			return( (CFSecJpaTableInfoBySchemaRTCodeIdxKey)key );
		}
		else {
			CFSecJpaTableInfoBySchemaRTCodeIdxKey mapped = new CFSecJpaTableInfoBySchemaRTCodeIdxKey();
			mapped.setRequiredRuntimeClassCode( key.getRequiredRuntimeClassCode() );
			return( mapped );
		}
	}

    @Override
    public ICFSecTableInfo newRec() {
        ICFSecTableInfo rec =
            new CFSecJpaTableInfo();
        return( rec );
    }

	public CFSecJpaTableInfo ensureRec(ICFSecTableInfo rec) {
		if( rec == null ) {
			return( null );
		}
		else if (rec instanceof CFSecJpaTableInfo) {
			return( (CFSecJpaTableInfo)rec );
		}
		else {
			CFSecJpaTableInfo mapped = new CFSecJpaTableInfo();
			mapped.set(rec);
			return( mapped );
		}
	}

    @Override
    public ICFSecTableInfoH newHRec() {
        ICFSecTableInfoH hrec =
            new CFSecJpaTableInfoH();
        return( hrec );
    }

	public CFSecJpaTableInfoH ensureHRec(ICFSecTableInfoH hrec) {
		if (hrec == null) {
			return( null );
		}
		else if( hrec instanceof CFSecJpaTableInfoH) {
			return( (CFSecJpaTableInfoH)hrec );
		}
		else {
			CFSecJpaTableInfoH mapped = new CFSecJpaTableInfoH();
			mapped.set(hrec);
			return( mapped );
		}
	}
}
